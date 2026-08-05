import re

class SynterPromptSanitizer:
    INJECTION_PATTERNS = [
        re.compile(r'system:\s*override', re.IGNORECASE),
        re.compile(r'ignore\s+(all\s+)?previous\s+instructions', re.IGNORECASE),
        re.compile(r'you\s+are\s+now\s+a', re.IGNORECASE),
        re.compile(r'<system_reminder>', re.IGNORECASE),
        re.compile(r'</system_reminder>', re.IGNORECASE),
        re.compile(r'eval\(.*\)', re.IGNORECASE),
        re.compile(r'exec\(.*\)', re.IGNORECASE),
        re.compile(r'import\s+os;?\s*os\.system', re.IGNORECASE)
    ]

    @classmethod
    def sanitize_external_text(cls, input_text: str) -> str:
        """
        Sanitizes external text (scraped web pages, ad copy, external API inputs)
        to remove indirect prompt injection vectors before passing into agent context.
        """
        if not input_text or not isinstance(input_text, str):
            return ""

        sanitized = input_text
        for pattern in cls.INJECTION_PATTERNS:
            sanitized = pattern.sub('[REDACTED_PROMPT_INJECTION]', sanitized)

        return sanitized
