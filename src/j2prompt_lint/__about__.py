from __future__ import annotations
__version__ = '0.1.0'
PROJECT_URL = 'https://github.com/center4aai/j2prompt-lint/'

def docs_url(rule: str) -> str:
    return f'{PROJECT_URL}#{rule.lower()}'
