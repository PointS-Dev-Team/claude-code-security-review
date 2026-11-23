#!/usr/bin/env python3
"""
Simplified PR Security Audit for GitHub Actions
Runs Claude Code security audit on current working directory and outputs findings to stdout
"""

import os
import sys
import json
import subprocess
import requests
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import re
import time
import fnmatch

# Import existing components we can reuse
from claudecode.prompts import get_security_audit_prompt
from claudecode.findings_filter import FindingsFilter
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.constants import (
    EXIT_CONFIGURATION_ERROR,
    DEFAULT_CLAUDE_MODEL,
    EXIT_SUCCESS,
    EXIT_GENERAL_ERROR,
    SUBPROCESS_TIMEOUT
)
from claudecode.logger import get_logger

logger = get_logger(__name__)

class ConfigurationError(ValueError):
    """Raised when configuration is invalid or missing."""
    pass

class AuditError(ValueError):
    """Raised when security audit operations fail."""
    pass

# The files API's page size, and its pages up to the 3000 files GitHub lists for a PR.
FILES_PER_PAGE = 100
MAX_FILES_PAGES = 30

# Stands in for the changes of a file the files API gives no patch for. It starts with a letter, which no patch line does.
NO_PATCH_MARKER = "Patch not available: the GitHub API gave no patch for this file (binary, too large, or no line changes)."

class GitHubActionClient:
    """Simplified GitHub API client for GitHub Actions environment."""
    
    def __init__(self):
        """Initialize GitHub client using environment variables."""
        self.github_token = os.environ.get('GITHUB_TOKEN')
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable required")
            
        self.headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        # Get excluded directories from environment
        exclude_dirs = os.environ.get('EXCLUDE_DIRECTORIES', '')
        self.excluded_dirs = [d.strip() for d in exclude_dirs.split(',') if d.strip()] if exclude_dirs else []
        if self.excluded_dirs:
            print(f"[Debug] Excluded directories: {self.excluded_dirs}", file=sys.stderr)

        # Files left out by name: comma-separated fnmatch patterns on the repository path, where * also crosses a /, so
        # "*/Migrations/*.Designer.cs" leaves out generated EF Designers in any Migrations folder and nothing else there.
        exclude_files = os.environ.get('EXCLUDE_FILES', '')
        self.excluded_file_patterns = [p.strip() for p in exclude_files.split(',') if p.strip()]
        if self.excluded_file_patterns:
            print(f"[Debug] Excluded file patterns: {self.excluded_file_patterns}", file=sys.stderr)
        # The PR's files left out of the scan, by either rule, for the job's summary.
        self.excluded_files: List[str] = []

    def get_pr_data(self, repo_name: str, pr_number: int) -> Dict[str, Any]:
        """Get PR metadata and files from GitHub API.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Dictionary containing PR data
        """
        # Get PR metadata
        pr_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        response = requests.get(pr_url, headers=self.headers)
        response.raise_for_status()
        pr_data = response.json()
        
        files_data = self._get_pr_files(repo_name, pr_number)
        self.excluded_files = [f['filename'] for f in files_data if self._is_excluded(f['filename'])]
        
        return {
            'number': pr_data['number'],
            'title': pr_data['title'],
            'body': pr_data.get('body', ''),
            'user': pr_data['user']['login'],
            'created_at': pr_data['created_at'],
            'updated_at': pr_data['updated_at'],
            'state': pr_data['state'],
            'head': {
                'ref': pr_data['head']['ref'],
                'sha': pr_data['head']['sha'],
                'repo': {
                    'full_name': pr_data['head']['repo']['full_name'] if pr_data['head']['repo'] else repo_name
                }
            },
            'base': {
                'ref': pr_data['base']['ref'],
                'sha': pr_data['base']['sha']
            },
            'files': [
                {
                    'filename': f['filename'],
                    'status': f['status'],
                    'additions': f['additions'],
                    'deletions': f['deletions'],
                    'changes': f['changes'],
                    'patch': f.get('patch', '')
                }
                for f in files_data
                if not self._is_excluded(f['filename'])
            ],
            'additions': pr_data['additions'],
            'deletions': pr_data['deletions'],
            'changed_files': pr_data['changed_files']
        }
    
    def get_pr_diff(self, repo_name: str, pr_number: int) -> str:
        """Get complete PR diff in unified format.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Complete PR diff in unified format
        """
        url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        headers = dict(self.headers)
        headers['Accept'] = 'application/vnd.github.diff'
        
        response = requests.get(url, headers=headers)
        # GitHub refuses the diff media type with 406 Not Acceptable for a PR past its diff limit (about 300 files),
        # so such a PR's diff is put together from its files' patches instead.
        if response.status_code == 406:
            logger.info("GitHub refused the PR's diff as too large (406); building it from the files API")
            diff = self._filter_generated_files(self._diff_from_files(self._get_pr_files(repo_name, pr_number)))
            without_patch = sum(1 for line in diff.splitlines() if line == NO_PATCH_MARKER)
            if without_patch:
                logger.warning(f"{without_patch} file(s) in the PR's diff have no patch from the GitHub API "
                               f"(binary, too large, or no line changes): the diff names them without their changes")
            return diff
        response.raise_for_status()

        return self._filter_generated_files(response.text)

    def _get_pr_files(self, repo_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Every file of the PR from the files API, read page by page (GitHub lists at most 3000)."""
        files_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files?per_page={FILES_PER_PAGE}"
        files: List[Dict[str, Any]] = []
        for page in range(1, MAX_FILES_PAGES + 1):
            # The first page keeps the URL a PR of up to 100 files has always used.
            url = files_url if page == 1 else f"{files_url}&page={page}"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            page_files = response.json()
            files.extend(page_files)
            if len(page_files) < FILES_PER_PAGE or 'rel="next"' not in response.headers.get('Link', ''):
                return files
        logger.warning(f"The PR lists more than {len(files)} files: GitHub returns no more, so the rest aren't in the scan")
        return files

    @staticmethod
    def _diff_from_files(files: List[Dict[str, Any]]) -> str:
        """A unified diff put together from the files API's per-file patches, one section per file."""
        sections = []
        for f in files:
            new_path = f['filename']
            old_path = f.get('previous_filename') or new_path
            section = f"diff --git a/{old_path} b/{new_path}\n"
            patch = f.get('patch')
            if not patch:
                # A binary or too-large file has no patch: it is named, with a marker, rather than left out.
                sections.append(f"{section}{NO_PATCH_MARKER}\n")
                continue
            old_side = '/dev/null' if f.get('status') == 'added' else f"a/{old_path}"
            new_side = '/dev/null' if f.get('status') == 'removed' else f"b/{new_path}"
            section += f"--- {old_side}\n+++ {new_side}\n{patch}"
            sections.append(section if section.endswith('\n') else section + '\n')
        return ''.join(sections)

    def _is_excluded(self, filepath: str) -> bool:
        """Check if a file should be excluded based on directory patterns or file patterns."""
        for pattern in self.excluded_file_patterns:
            normalized_pattern = pattern[2:] if pattern.startswith('./') else pattern
            if fnmatch.fnmatchcase(filepath, normalized_pattern):
                return True
        for excluded_dir in self.excluded_dirs:
            # Normalize excluded directory (remove leading ./ if present)
            if excluded_dir.startswith('./'):
                normalized_excluded = excluded_dir[2:]
            else:
                normalized_excluded = excluded_dir
            
            # Check if file starts with excluded directory
            if filepath.startswith(excluded_dir + '/'):
                return True
            if filepath.startswith(normalized_excluded + '/'):
                return True
            
            # Check if excluded directory appears anywhere in the path
            if '/' + normalized_excluded + '/' in filepath:
                return True
            
        return False
    
    def _filter_generated_files(self, diff_text: str) -> str:
        """Filter out generated files and excluded directories from diff content."""
        
        file_sections = re.split(r'(?=^diff --git)', diff_text, flags=re.MULTILINE)
        filtered_sections = []
        
        for section in file_sections:
            if not section.strip():
                continue
                
            # Skip generated files
            if ('@generated by' in section or 
                '@generated' in section or 
                'Code generated by OpenAPI Generator' in section or
                'Code generated by protoc-gen-go' in section):
                continue
            
            # Extract filename from diff header
            match = re.match(r'^diff --git a/(.*?) b/', section)
            if match:
                filename = match.group(1)
                if self._is_excluded(filename):
                    print(f"[Debug] Filtering out excluded file: {filename}", file=sys.stderr)
                    continue
            
            filtered_sections.append(section)
        
        return ''.join(filtered_sections)


# Claude Code's limit on piped stdin, where the prompt goes.
MAX_STDIN_BYTES = 10 * 1024 * 1024


class SimpleClaudeRunner:
    """Simplified Claude Code runner for GitHub Actions."""
    
    def __init__(self, timeout_minutes: Optional[int] = None):
        """Initialize Claude runner.
        
        Args:
            timeout_minutes: Timeout for Claude execution (defaults to SUBPROCESS_TIMEOUT)
        """
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT
    
    def run_security_audit(self, repo_dir: Path, prompt: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Run Claude Code security audit.
        
        Args:
            repo_dir: Path to repository directory
            prompt: Security audit prompt
            
        Returns:
            Tuple of (success, error_message, parsed_results)
        """
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}
        
        # Check prompt size
        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB", file=sys.stderr)
        # Claude Code refuses piped stdin over 10 MB ("piped stdin input exceeds 10MB", exit 1) before it reads the prompt,
        # so such a prompt goes straight to the caller's retry without the diff, as one it calls too long does.
        if prompt_size > MAX_STDIN_BYTES:
            print(f"[Info] Prompt over Claude Code's stdin limit ({prompt_size} bytes), not sent", file=sys.stderr)
            return False, "PROMPT_TOO_LONG", {}
        
        try:
            # Construct Claude Code command
            # Use stdin for prompt to avoid "argument list too long" error
            cmd = [
                'claude',
                '--output-format', 'json',
                '--model', DEFAULT_CLAUDE_MODEL,
                '--disallowed-tools', 'Bash(ps:*)'
            ]
            
            # Run Claude Code with retry logic
            NUM_RETRIES = 3
            for attempt in range(NUM_RETRIES):
                result = subprocess.run(
                    cmd,
                    input=prompt,  # Pass prompt via stdin
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds
                )
                
                if result.returncode != 0:
                    # Claude Code refuses a prompt over its limit before calling the API, exiting 1 with its result
                    # ("Prompt is too long") on stdout. Retrying sends the same prompt, so it goes straight to the caller's
                    # retry without the diff.
                    parsed_ok, parsed_failure = parse_json_with_fallbacks(result.stdout, "Claude Code output")
                    if parsed_ok and self._is_prompt_too_long(parsed_failure):
                        return False, "PROMPT_TOO_LONG", {}
                    if attempt == NUM_RETRIES - 1:
                        error_details = f"Claude Code execution failed with return code {result.returncode}\n"
                        error_details += f"Stderr: {result.stderr}\n"
                        error_details += f"Stdout: {result.stdout[:500]}..."  # First 500 chars
                        return False, error_details, {}
                    else:
                        time.sleep(5*attempt)
                        # Note: We don't do exponential backoff here to keep the runtime reasonable
                        continue  # Retry
                
                # Parse JSON output
                success, parsed_result = parse_json_with_fallbacks(result.stdout, "Claude Code output")
                
                if success:
                    # Check for "Prompt is too long" error that should trigger retry without diff
                    if self._is_prompt_too_long(parsed_result):
                        return False, "PROMPT_TOO_LONG", {}
                    
                    # Check for error_during_execution that should trigger retry
                    if (isinstance(parsed_result, dict) and 
                        parsed_result.get('type') == 'result' and 
                        parsed_result.get('subtype') == 'error_during_execution' and
                        attempt == 0):
                        continue  # Retry
                    
                    # Extract security findings
                    parsed_results = self._extract_security_findings(parsed_result)
                    return True, "", parsed_results
                else:
                    if attempt == 0:
                        continue  # Retry once
                    else:
                        return False, "Failed to parse Claude output", {}
            
            return False, "Unexpected error in retry logic", {}
            
        except subprocess.TimeoutExpired:
            return False, f"Claude Code execution timed out after {self.timeout_seconds // 60} minutes", {}
        except Exception as e:
            return False, f"Claude Code execution error: {str(e)}", {}
    
    @staticmethod
    def _is_prompt_too_long(parsed: Any) -> bool:
        """Whether Claude Code's JSON result is its refusal of a prompt over its limit, whatever its exit code."""
        if not isinstance(parsed, dict) or parsed.get('type') != 'result' or not parsed.get('is_error'):
            return False
        text = parsed.get('result')
        return isinstance(text, str) and text.strip().lower().startswith('prompt is too long')

    def _extract_security_findings(self, claude_output: Any) -> Dict[str, Any]:
        """Extract security findings from Claude's JSON response."""
        if isinstance(claude_output, dict):
            # Only accept Claude Code wrapper with result field
            # Direct format without wrapper is not supported
            if 'result' in claude_output:
                result_text = claude_output['result']
                if isinstance(result_text, str):
                    # Try to extract JSON from the result text
                    success, result_json = parse_json_with_fallbacks(result_text, "Claude result text")
                    if success and result_json and 'findings' in result_json:
                        return result_json
        
        # Return empty structure if no findings found
        return {
            'findings': [],
            'analysis_summary': {
                'files_reviewed': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'review_completed': False,
            }
        }
    
    
    def validate_claude_available(self) -> Tuple[bool, str]:
        """Validate that Claude Code is available."""
        try:
            result = subprocess.run(
                ['claude', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Also check if API key is configured
                api_key = os.environ.get('ANTHROPIC_API_KEY', '')
                if not api_key:
                    return False, "ANTHROPIC_API_KEY environment variable is not set"
                return True, ""
            else:
                error_msg = f"Claude Code returned exit code {result.returncode}"
                if result.stderr:
                    error_msg += f". Stderr: {result.stderr}"
                if result.stdout:
                    error_msg += f". Stdout: {result.stdout}"
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, "Claude Code command timed out"
        except FileNotFoundError:
            return False, "Claude Code is not installed or not in PATH"
        except Exception as e:
            return False, f"Failed to check Claude Code: {str(e)}"




def get_environment_config() -> Tuple[str, int]:
    """Get and validate environment configuration.
    
    Returns:
        Tuple of (repo_name, pr_number)
        
    Raises:
        ConfigurationError: If required environment variables are missing or invalid
    """
    repo_name = os.environ.get('GITHUB_REPOSITORY')
    pr_number_str = os.environ.get('PR_NUMBER')
    
    if not repo_name:
        raise ConfigurationError('GITHUB_REPOSITORY environment variable required')
    
    if not pr_number_str:
        raise ConfigurationError('PR_NUMBER environment variable required')
    
    try:
        pr_number = int(pr_number_str)
    except ValueError:
        raise ConfigurationError(f'Invalid PR_NUMBER: {pr_number_str}')
        
    return repo_name, pr_number


def initialize_clients() -> Tuple[GitHubActionClient, SimpleClaudeRunner]:
    """Initialize GitHub and Claude clients.
    
    Returns:
        Tuple of (github_client, claude_runner)
        
    Raises:
        ConfigurationError: If client initialization fails
    """
    try:
        github_client = GitHubActionClient()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize GitHub client: {str(e)}')
    
    try:
        claude_runner = SimpleClaudeRunner()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize Claude runner: {str(e)}')
        
    return github_client, claude_runner


def initialize_findings_filter(custom_filtering_instructions: Optional[str] = None) -> FindingsFilter:
    """Initialize findings filter based on environment configuration.
    
    Args:
        custom_filtering_instructions: Optional custom filtering instructions
        
    Returns:
        FindingsFilter instance
        
    Raises:
        ConfigurationError: If filter initialization fails
    """
    try:
        # Check if we should use Claude API filtering
        use_claude_filtering = os.environ.get('ENABLE_CLAUDE_FILTERING', 'false').lower() == 'true'
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        
        if use_claude_filtering and api_key:
            # Use full filtering with Claude API
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=True,
                api_key=api_key,
                custom_filtering_instructions=custom_filtering_instructions
            )
        else:
            # Fallback to filtering with hard rules only
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=False
            )
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize findings filter: {str(e)}')



def run_security_audit(claude_runner: SimpleClaudeRunner, prompt: str) -> Dict[str, Any]:
    """Run the security audit with Claude Code.
    
    Args:
        claude_runner: Claude runner instance
        prompt: The security audit prompt
        
    Returns:
        Audit results dictionary
        
    Raises:
        AuditError: If the audit fails
    """
    # Get repo directory from environment or use current directory
    repo_path = os.environ.get('REPO_PATH')
    repo_dir = Path(repo_path) if repo_path else Path.cwd()
    success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)
    
    if not success:
        raise AuditError(f'Security audit failed: {error_msg}')
        
    return results


def apply_findings_filter(findings_filter, original_findings: List[Dict[str, Any]], 
                         pr_context: Dict[str, Any], github_client: GitHubActionClient) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filter to reduce false positives.
    
    Args:
        findings_filter: Filter instance
        original_findings: Original findings from audit
        pr_context: PR context information
        github_client: GitHub client with exclusion logic
        
    Returns:
        Tuple of (kept_findings, excluded_findings, analysis_summary)
    """
    # Apply FindingsFilter
    filter_success, filter_results, filter_stats = findings_filter.filter_findings(
        original_findings, pr_context
    )
    
    if filter_success:
        kept_findings = filter_results.get('filtered_findings', [])
        excluded_findings = filter_results.get('excluded_findings', [])
        analysis_summary = filter_results.get('analysis_summary', {})
    else:
        # Filtering failed, keep all findings
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}
    
    # Apply final directory exclusion filtering
    final_kept_findings = []
    directory_excluded_findings = []
    
    for finding in kept_findings:
        if _is_finding_in_excluded_directory(finding, github_client):
            directory_excluded_findings.append(finding)
        else:
            final_kept_findings.append(finding)
    
    # Update excluded findings list
    all_excluded_findings = excluded_findings + directory_excluded_findings
    
    # Update analysis summary with directory filtering stats
    analysis_summary['directory_excluded_count'] = len(directory_excluded_findings)
    
    return final_kept_findings, all_excluded_findings, analysis_summary


def _is_finding_in_excluded_directory(finding: Dict[str, Any], github_client: GitHubActionClient) -> bool:
    """Check if a finding references a file in an excluded directory.
    
    Args:
        finding: Security finding dictionary
        github_client: GitHub client with exclusion logic
        
    Returns:
        True if finding should be excluded, False otherwise
    """
    file_path = finding.get('file', '')
    if not file_path:
        return False
    
    return github_client._is_excluded(file_path)


def main():
    """Main execution function for GitHub Action."""
    try:
        # Get environment configuration
        try:
            repo_name, pr_number = get_environment_config()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
        
        # Load custom filtering instructions if provided
        custom_filtering_instructions = None
        filtering_file = os.environ.get('FALSE_POSITIVE_FILTERING_INSTRUCTIONS', '')
        if filtering_file and Path(filtering_file).exists():
            try:
                with open(filtering_file, 'r', encoding='utf-8') as f:
                    custom_filtering_instructions = f.read()
                    logger.info(f"Loaded custom filtering instructions from {filtering_file}")
            except Exception as e:
                logger.warning(f"Failed to read filtering instructions file {filtering_file}: {e}")
        
        # Load custom security scan instructions if provided
        custom_scan_instructions = None
        scan_file = os.environ.get('CUSTOM_SECURITY_SCAN_INSTRUCTIONS', '')
        if scan_file and Path(scan_file).exists():
            try:
                with open(scan_file, 'r', encoding='utf-8') as f:
                    custom_scan_instructions = f.read()
                    logger.info(f"Loaded custom security scan instructions from {scan_file}")
            except Exception as e:
                logger.warning(f"Failed to read security scan instructions file {scan_file}: {e}")
        
        # Initialize components
        try:
            github_client, claude_runner = initialize_clients()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
            
        # Initialize findings filter
        try:
            findings_filter = initialize_findings_filter(custom_filtering_instructions)
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
        
        # Validate Claude Code is available
        claude_ok, claude_error = claude_runner.validate_claude_available()
        if not claude_ok:
            print(json.dumps({'error': f'Claude Code not available: {claude_error}'}))
            sys.exit(EXIT_GENERAL_ERROR)
        
        # Get PR data
        try:
            pr_data = github_client.get_pr_data(repo_name, pr_number)
            pr_diff = github_client.get_pr_diff(repo_name, pr_number)
        except Exception as e:
            print(json.dumps({'error': f'Failed to fetch PR data: {str(e)}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        # The files left out of the scan, named in the job's summary so a reader knows the scan didn't read them.
        summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
        if github_client.excluded_files and summary_path:
            try:
                with open(summary_path, 'a', encoding='utf-8') as summary:
                    summary.write(f"### Security review: {len(github_client.excluded_files)} file(s) left out of the scan\n\n")
                    summary.write("By `exclude-files` or `exclude-directories`. The scan didn't read these:\n\n")
                    for name in github_client.excluded_files:
                        summary.write(f"- `{name.replace('`', '')}`\n")
                    summary.write("\n")
            except OSError as e:
                print(f"[Warning] Couldn't write the left-out files to the job summary: {e}", file=sys.stderr)

        # Generate security audit prompt
        prompt = get_security_audit_prompt(pr_data, pr_diff, custom_scan_instructions=custom_scan_instructions)
        
        # Run Claude Code security audit
        # Get repo directory from environment or use current directory
        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)
        
        # If prompt is too long, retry without diff
        if not success and error_msg == "PROMPT_TOO_LONG":
            print(f"[Info] Prompt too long, retrying without diff. Original prompt length: {len(prompt)} characters", file=sys.stderr)
            prompt_without_diff = get_security_audit_prompt(pr_data, pr_diff, include_diff=False, custom_scan_instructions=custom_scan_instructions)
            print(f"[Info] New prompt length: {len(prompt_without_diff)} characters", file=sys.stderr)
            success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt_without_diff)
            if not success and error_msg == "PROMPT_TOO_LONG":
                error_msg = (f"the pull request is too large to scan: its prompt was too long with its diff "
                             f"({len(prompt.encode('utf-8'))} bytes) and without it ({len(prompt_without_diff.encode('utf-8'))} bytes)")

        if not success:
            print(json.dumps({'error': f'Security audit failed: {error_msg}'}))
            sys.exit(EXIT_GENERAL_ERROR)
        
        # Filter findings to reduce false positives
        original_findings = results.get('findings', [])
        
        # Prepare PR context for better filtering
        pr_context = {
            'repo_name': repo_name,
            'pr_number': pr_number,
            'title': pr_data.get('title', ''),
            'description': pr_data.get('body', '')
        }
        
        # Apply findings filter (including final directory exclusion)
        kept_findings, excluded_findings, analysis_summary = apply_findings_filter(
            findings_filter, original_findings, pr_context, github_client
        )
        
        # Prepare output
        output = {
            'pr_number': pr_number,
            'repo': repo_name,
            'findings': kept_findings,
            'analysis_summary': results.get('analysis_summary', {}),
            'filtering_summary': {
                'total_original_findings': len(original_findings),
                'excluded_findings': len(excluded_findings),
                'kept_findings': len(kept_findings),
                'filter_analysis': analysis_summary,
                'excluded_findings_details': excluded_findings  # Include full details of what was filtered
            }
        }
        
        # Output JSON to stdout
        print(json.dumps(output, indent=2))
        
        # Exit with appropriate code
        high_severity_count = len([f for f in kept_findings if f.get('severity', '').upper() == 'HIGH'])
        sys.exit(EXIT_GENERAL_ERROR if high_severity_count > 0 else EXIT_SUCCESS)
        
    except Exception as e:
        print(json.dumps({'error': f'Unexpected error: {str(e)}'}))
        sys.exit(EXIT_CONFIGURATION_ERROR)


if __name__ == '__main__':
    main()
