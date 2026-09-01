"""
Constants and configuration values for ClaudeCode.
"""

import os

# API Configuration
# Fork patch: fallback was claude-opus-4-1-20250805, whose retirement date
# (2026-08-05) has passed. An unset or empty CLAUDE_MODEL landed here, which put
# both the scan and the filter preflight on a dead model. Fall back to something
# live so a missing env var degrades to "wrong tier" rather than "404".
DEFAULT_CLAUDE_MODEL = os.environ.get('CLAUDE_MODEL') or 'claude-opus-5'
DEFAULT_TIMEOUT_SECONDS = 180  # 3 minutes
DEFAULT_MAX_RETRIES = 3
RATE_LIMIT_BACKOFF_MAX = 30  # Maximum backoff time for rate limits

# Token Limits
PROMPT_TOKEN_LIMIT = 16384  # 16k tokens max for claude-opus-4

# Exit Codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2

# Subprocess Configuration
SUBPROCESS_TIMEOUT = 1200  # 20 minutes for Claude Code execution

