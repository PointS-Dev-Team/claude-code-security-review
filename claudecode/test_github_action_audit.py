#!/usr/bin/env python3
"""
Pytest tests for GitHub Action audit script components.
"""


class TestImports:
    """Test that all required modules can be imported."""
    
    def test_main_module_import(self):
        """Test that the main module can be imported."""
        from claudecode import github_action_audit
        assert hasattr(github_action_audit, 'GitHubActionClient')
        assert hasattr(github_action_audit, 'SimpleClaudeRunner')
        # SimpleFindingsFilter was removed
        assert hasattr(github_action_audit, 'main')
    
    def test_component_imports(self):
        """Test that all component modules can be imported."""
        from claudecode.prompts import get_security_audit_prompt
        from claudecode.json_parser import parse_json_with_fallbacks, extract_json_from_text
        
        # Verify they're callable/usable
        assert callable(get_security_audit_prompt)
        assert callable(parse_json_with_fallbacks)
        assert callable(extract_json_from_text)


class TestHardExclusionRules:
    """Test the HardExclusionRules patterns."""
    
    def test_dos_patterns(self):
        """Test DOS pattern exclusions."""
        from claudecode.findings_filter import HardExclusionRules
        
        dos_findings = [
            {'description': 'Potential denial of service vulnerability'},
            {'description': 'DOS attack through resource exhaustion'},
            {'description': 'Infinite loop causing resource exhaustion'},
        ]
        
        for finding in dos_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert 'dos' in reason.lower()
    
    def test_rate_limiting_patterns(self):
        """Test rate limiting pattern exclusions."""
        from claudecode.findings_filter import HardExclusionRules
        
        rate_limit_findings = [
            {'description': 'Missing rate limiting on endpoint'},
            {'description': 'No rate limit implemented for API'},
            {'description': 'Implement rate limiting for this route'},
        ]
        
        for finding in rate_limit_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert 'rate limit' in reason.lower()
    
    def test_open_redirect_patterns(self):
        """Test open redirect pattern exclusions."""
        from claudecode.findings_filter import HardExclusionRules
        
        redirect_findings = [
            {'description': 'Open redirect vulnerability found'},
            {'description': 'Unvalidated redirect in URL parameter'},
            {'description': 'Redirect attack possible through user input'},
        ]
        
        for finding in redirect_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert 'open redirect' in reason.lower()
    
    def test_markdown_file_exclusion(self):
        """Test that findings in .md files are excluded."""
        from claudecode.findings_filter import HardExclusionRules
        
        md_findings = [
            {'file': 'README.md', 'description': 'SQL injection vulnerability'},
            {'file': 'docs/security.md', 'description': 'Command injection found'},
            {'file': 'CHANGELOG.MD', 'description': 'XSS vulnerability'},  # Test case insensitive
            {'file': 'path/to/file.Md', 'description': 'Path traversal'},  # Mixed case
        ]
        
        for finding in md_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert 'markdown' in reason.lower()
    
    def test_non_markdown_files_not_excluded(self):
        """Test that findings in non-.md files are not excluded due to file extension."""
        from claudecode.findings_filter import HardExclusionRules
        
        non_md_findings = [
            {'file': 'main.py', 'description': 'SQL injection vulnerability'},
            {'file': 'server.js', 'description': 'Command injection found'},
            {'file': 'index.html', 'description': 'XSS vulnerability'},
            {'file': 'config.yml', 'description': 'Hardcoded credentials'},
            {'file': 'README.txt', 'description': 'Path traversal'},
            {'file': 'file.mdx', 'description': 'Security issue'},  # Not .md
        ]
        
        for finding in non_md_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            # Should not be excluded for being a markdown file
            # (might be excluded for other reasons like DOS patterns)
            if reason:
                assert 'markdown' not in reason.lower()
    
    def test_keeps_real_vulnerabilities(self):
        """Test that real vulnerabilities are not excluded."""
        from claudecode.findings_filter import HardExclusionRules
        
        real_vulns = [
            {'file': 'auth.py', 'description': 'SQL injection in user authentication'},
            {'file': 'exec.js', 'description': 'Command injection through user input'},
            {'file': 'comments.php', 'description': 'Cross-site scripting in comment field'},
            {'file': 'upload.go', 'description': 'Path traversal in file upload'},
        ]
        
        for finding in real_vulns:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is None


class TestJSONParser:
    """Test JSON parsing utilities."""
    
    def test_parse_valid_json(self):
        """Test parsing valid JSON."""
        from claudecode.json_parser import parse_json_with_fallbacks
        
        valid_json = '{"test": "data", "number": 123}'
        success, result = parse_json_with_fallbacks(valid_json, "test")
        
        assert success is True
        assert result == {"test": "data", "number": 123}
    
    def test_parse_invalid_json(self):
        """Test parsing invalid JSON."""
        from claudecode.json_parser import parse_json_with_fallbacks
        
        invalid_json = '{invalid json}'
        success, result = parse_json_with_fallbacks(invalid_json, "test")
        
        assert success is False
        assert 'error' in result
        assert 'Invalid JSON response' in result['error']
    
    def test_extract_json_from_text(self):
        """Test extracting JSON from mixed text."""
        from claudecode.json_parser import extract_json_from_text
        
        mixed_text = 'Some text before {"key": "value"} some text after'
        result = extract_json_from_text(mixed_text)
        
        assert result == {"key": "value"}
    
    def test_extract_json_from_text_no_json(self):
        """Test extracting JSON when none exists."""
        from claudecode.json_parser import extract_json_from_text
        
        plain_text = 'This is just plain text with no JSON'
        result = extract_json_from_text(plain_text)
        
        assert result is None


class TestPromptsModule:
    """Test the prompts module."""
    
    def test_get_security_audit_prompt(self):
        """Test security audit prompt generation."""
        from claudecode.prompts import get_security_audit_prompt
        
        pr_data = {
            'number': 123,
            'title': 'Test PR',
            'body': 'Test description',
            'user': 'testuser',
            'changed_files': 1,
            'additions': 10,
            'deletions': 5,
            'head': {
                'repo': {
                    'full_name': 'owner/repo'
                }
            },
            'files': [
                {
                    'filename': 'test.py',
                    'status': 'modified',
                    'additions': 10,
                    'deletions': 5,
                    'patch': '@@ -1,5 +1,10 @@\n+added line'
                }
            ]
        }
        
        pr_diff = "diff --git a/test.py b/test.py\n+added line"
        
        prompt = get_security_audit_prompt(pr_data, pr_diff)
        
        assert isinstance(prompt, str)
        assert 'security' in prompt.lower()
        assert 'PR #123' in prompt
        assert 'test.py' in prompt


class TestDeploymentPRDetection:
    """Test deployment PR title pattern matching."""
    
    def test_deployment_pr_patterns(self):
        """Test that deployment PR titles are correctly identified."""
        import re
        
        deployment_pattern = r'^Deploy\s+[a-f0-9]{6,}\s+to\s+(production|staging|development|production-services)'
        
        # These should match
        deployment_titles = [
            "Deploy 53f395b0 to production-services",
            "Deploy af179b5b to production",
            "Deploy 1a3cb909 to production",
            "Deploy 49c09ea5 to production-services",
            "Deploy 8e7acc60 to production",
            "Deploy e0b1fe0b to production-services",
            "Deploy c53e6010 to production",
            "Deploy 42c4a061 to production",
            "Deploy 9de55976 to production-services",
            "deploy abcdef123456 to staging",  # lowercase should work
            "DEPLOY ABCDEF01 TO DEVELOPMENT",  # uppercase should work
        ]
        
        for title in deployment_titles:
            assert re.match(deployment_pattern, title, re.IGNORECASE), f"Failed to match deployment PR: {title}"
    
    def test_non_deployment_pr_patterns(self):
        """Test that non-deployment PR titles are not matched."""
        import re
        
        deployment_pattern = r'^Deploy\s+[a-f0-9]{6,}\s+to\s+(production|staging|development|production-services)'
        
        # These should NOT match
        non_deployment_titles = [
            "Add new feature",
            "Fix bug in deployment script",
            "Update deployment documentation",
            "Deploy new feature to production",  # No commit hash
            "Deploy abc to production",  # Too short hash
            "Deploy 12345g to production",  # Non-hex character
            "Preparing deploy af179b5b to production",  # Doesn't start with Deploy
            "Deploy af179b5b to testing",  # Wrong environment
            "Deploy af179b5b",  # Missing environment
            "af179b5b to production",  # Missing Deploy prefix
        ]
        
        for title in non_deployment_titles:
            assert not re.match(deployment_pattern, title, re.IGNORECASE), f"Incorrectly matched non-deployment PR: {title}"



class TestLargePRDiffFallback:
    """A PR too large for GitHub's diff media type gets its diff from the files API, read page by page."""

    DIFF_URL = 'https://api.github.com/repos/owner/repo/pulls/123'
    FILES_URL = 'https://api.github.com/repos/owner/repo/pulls/123/files?per_page=100'

    @staticmethod
    def _client():
        import os
        from unittest.mock import patch
        from claudecode.github_action_audit import GitHubActionClient
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            return GitHubActionClient()

    @staticmethod
    def _diff_refused():
        """The diff request's answer for a large PR: 406, which raise_for_status would raise."""
        from unittest.mock import Mock
        import requests
        response = Mock()
        response.status_code = 406
        response.raise_for_status.side_effect = requests.HTTPError(
            "406 Client Error: Not Acceptable for url: https://api.github.com/repos/owner/repo/pulls/123")
        return response

    @staticmethod
    def _files_page(files, next_page=None):
        from unittest.mock import Mock
        response = Mock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.return_value = files
        response.headers = {'Link': f'<https://api.github.com/x?page={next_page}>; rel="next"'} if next_page else {}
        return response

    def test_406_on_the_diff_builds_it_from_each_files_patch(self):
        from unittest.mock import patch
        files = [
            {'filename': 'src/app.py', 'status': 'modified', 'patch': '@@ -1 +1 @@\n-old\n+new'},
            {'filename': 'src/new.py', 'status': 'added', 'patch': '@@ -0,0 +1 @@\n+created'},
            {'filename': 'src/gone.py', 'status': 'removed', 'patch': '@@ -1 +0,0 @@\n-deleted'},
            {'filename': 'src/to.py', 'previous_filename': 'src/from.py', 'status': 'renamed',
             'patch': '@@ -1 +1 @@\n-a\n+b'},
        ]
        client = self._client()
        with patch('requests.get') as mock_get:
            mock_get.side_effect = [self._diff_refused(), self._files_page(files)]
            result = client.get_pr_diff('owner/repo', 123)

        assert mock_get.call_args_list[1][0][0] == self.FILES_URL
        assert result == (
            "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n"
            "diff --git a/src/new.py b/src/new.py\n--- /dev/null\n+++ b/src/new.py\n@@ -0,0 +1 @@\n+created\n"
            "diff --git a/src/gone.py b/src/gone.py\n--- a/src/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-deleted\n"
            "diff --git a/src/from.py b/src/to.py\n--- a/src/from.py\n+++ b/src/to.py\n@@ -1 +1 @@\n-a\n+b\n"
        )

    def test_a_files_list_over_several_pages_is_read_whole(self):
        from unittest.mock import patch
        def page_of(start, count):
            return [{'filename': f'f{i}.py', 'status': 'modified', 'additions': 1, 'deletions': 0, 'changes': 1,
                     'patch': '@@ -1 +1 @@\n+x'} for i in range(start, start + count)]
        pr_response = self._files_page(None)
        pr_response.json.return_value = {
            'number': 123, 'title': 'Big', 'body': '', 'user': {'login': 'u'},
            'created_at': '', 'updated_at': '', 'state': 'open',
            'head': {'ref': 'h', 'sha': 'abc', 'repo': {'full_name': 'owner/repo'}},
            'base': {'ref': 'main', 'sha': 'def'}, 'additions': 250, 'deletions': 0, 'changed_files': 250,
        }
        client = self._client()
        with patch('requests.get') as mock_get:
            mock_get.side_effect = [pr_response, self._files_page(page_of(0, 100), next_page=2),
                                    self._files_page(page_of(100, 100), next_page=3),
                                    self._files_page(page_of(200, 50))]
            result = client.get_pr_data('owner/repo', 123)

        assert [c[0][0] for c in mock_get.call_args_list[1:]] == [
            self.FILES_URL, self.FILES_URL + '&page=2', self.FILES_URL + '&page=3']
        assert len(result['files']) == 250
        assert result['files'][249]['filename'] == 'f249.py'
        assert client.scan_notes == []

    def test_a_file_without_a_patch_is_named_with_the_not_available_marker(self):
        from unittest.mock import patch
        from claudecode.github_action_audit import NO_PATCH_MARKER
        files = [
            {'filename': 'img/logo.png', 'status': 'modified'},
            {'filename': 'src/app.py', 'status': 'modified', 'patch': '@@ -1 +1 @@\n+x'},
        ]
        client = self._client()
        with patch('requests.get') as mock_get, patch('claudecode.github_action_audit.logger') as mock_logger:
            mock_get.side_effect = [self._diff_refused(), self._files_page(files)]
            result = client.get_pr_diff('owner/repo', 123)

        assert result.startswith(f"diff --git a/img/logo.png b/img/logo.png\n{NO_PATCH_MARKER}\ndiff --git a/src/app.py")
        assert mock_logger.warning.call_count == 1
        assert mock_logger.warning.call_args[0][0].startswith('1 file(s)')

    def test_a_diff_error_other_than_406_still_raises(self):
        from unittest.mock import Mock, patch
        import pytest
        import requests
        response = Mock()
        response.status_code = 500
        response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        client = self._client()
        with patch('requests.get') as mock_get:
            mock_get.return_value = response
            with pytest.raises(requests.HTTPError, match="500 Server Error"):
                client.get_pr_diff('owner/repo', 123)
        assert mock_get.call_count == 1

    def test_the_marker_count_splits_lines_on_newlines_only(self):
        from unittest.mock import patch
        from claudecode.github_action_audit import NO_PATCH_MARKER
        # A form feed in a patch line is no line break: splitlines() would count the marker after it as a second line.
        files = [
            {'filename': 'img/logo.png', 'status': 'modified'},
            {'filename': 'src/app.py', 'status': 'modified', 'patch': f'@@ -1 +1 @@\n+x\x0c{NO_PATCH_MARKER}'},
        ]
        client = self._client()
        with patch('requests.get') as mock_get:
            mock_get.side_effect = [self._diff_refused(), self._files_page(files)]
            client.get_pr_diff('owner/repo', 123)

        assert len(client.scan_notes) == 1
        assert client.scan_notes[0].startswith('1 file(s) in the PR')


class TestScanNotes:
    """What the scan has of a PR short of all of it is said in its results and the job's summary, not only the log."""

    PR = {
        'number': 123, 'title': 'Big', 'body': '', 'user': {'login': 'u'},
        'created_at': '', 'updated_at': '', 'state': 'open',
        'head': {'ref': 'h', 'sha': 'abc', 'repo': {'full_name': 'owner/repo'}},
        'base': {'ref': 'main', 'sha': 'def'}, 'additions': 1, 'deletions': 0,
    }
    AUDIT_OK = (True, "", {'findings': [], 'analysis_summary': {'files_reviewed': 1, 'review_completed': True}})

    @staticmethod
    def _response(json_value=None, text='', next_page=False):
        from unittest.mock import Mock
        response = Mock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.return_value = json_value
        response.text = text
        response.headers = {'Link': '<https://api.github.com/x?page=2>; rel="next"'} if next_page else {}
        return response

    def _run_main(self, tmp_path, capsys, changed_files, pages, audit_results):
        """Runs main on a PR whose files API answers `pages`, with Claude Code answering `audit_results` in turn."""
        import json
        import os
        import pytest
        from unittest.mock import Mock, patch
        from claudecode.github_action_audit import main
        responses = [self._response(dict(self.PR, changed_files=changed_files))]
        responses += [self._response(page, next_page=i < len(pages) - 1) for i, page in enumerate(pages)]
        responses.append(self._response(text='diff --git a/f0.py b/f0.py\n--- a/f0.py\n+++ b/f0.py\n@@ -1 +1 @@\n+x\n'))
        runner = Mock()
        runner.validate_claude_available.return_value = (True, "")
        runner.run_security_audit.side_effect = audit_results
        summary = tmp_path / 'summary.md'
        env = {'GITHUB_REPOSITORY': 'owner/repo', 'PR_NUMBER': '123', 'GITHUB_TOKEN': 't',
               'GITHUB_STEP_SUMMARY': str(summary), 'REPO_PATH': str(tmp_path)}
        with patch.dict(os.environ, env), patch('requests.get', side_effect=responses), \
                patch('claudecode.github_action_audit.SimpleClaudeRunner', return_value=runner), \
                patch('claudecode.github_action_audit.FindingsFilter') as filter_class:
            filter_class.return_value.filter_findings.return_value = (
                True, {'filtered_findings': [], 'excluded_findings': [], 'analysis_summary': {}}, None)
            with pytest.raises(SystemExit) as exit_info:
                main()
        assert exit_info.value.code == 0
        results = json.loads(capsys.readouterr().out)
        return results, (summary.read_text(encoding='utf-8') if summary.exists() else '')

    @staticmethod
    def _files(start, count):
        return [{'filename': f'f{i}.py', 'status': 'modified', 'additions': 1, 'deletions': 0, 'changes': 1,
                 'patch': '@@ -1 +1 @@\n+x'} for i in range(start, start + count)]

    def test_files_past_githubs_list_are_counted_in_the_results_and_the_summary(self, tmp_path, capsys):
        # At GitHub's cap its last page is full and has no link to a next one, so only the PR's count shows the rest.
        results, summary = self._run_main(tmp_path, capsys, changed_files=250,
                                          pages=[self._files(0, 100), self._files(100, 100)],
                                          audit_results=[self.AUDIT_OK])

        line = "GitHub listed 200 of the PR's 250 changed files; the other 50 aren't in this scan"
        assert results['scan_notes'] == [line]
        assert f"- {line}\n" in summary

    def test_the_retry_without_the_diff_is_said_in_the_results_and_the_summary(self, tmp_path, capsys):
        from claudecode.github_action_audit import DIFF_LEFT_OUT_NOTE
        results, summary = self._run_main(tmp_path, capsys, changed_files=1, pages=[self._files(0, 1)],
                                          audit_results=[(False, "PROMPT_TOO_LONG", {}), self.AUDIT_OK])

        assert results['scan_notes'] == [DIFF_LEFT_OUT_NOTE]
        assert f"- {DIFF_LEFT_OUT_NOTE}\n" in summary

    def test_a_whole_scan_has_no_notes_and_writes_none_to_the_summary(self, tmp_path, capsys):
        results, summary = self._run_main(tmp_path, capsys, changed_files=1, pages=[self._files(0, 1)],
                                          audit_results=[self.AUDIT_OK])

        assert results['scan_notes'] == []
        assert summary == ''
