import re
from typing import Dict, List

class SynterPromptSanitizer:
    INJECTION_RULES = [
        ("system_override", re.compile(r'system:\s*override', re.IGNORECASE)),
        ("ignore_previous_instructions", re.compile(r'ignore\s+(all\s+)?previous\s+instructions', re.IGNORECASE)),
        ("role_reassignment", re.compile(r'you\s+are\s+now\s+a', re.IGNORECASE)),
        ("system_reminder_tag", re.compile(r'<system_reminder>', re.IGNORECASE)),
        ("system_reminder_close_tag", re.compile(r'</system_reminder>', re.IGNORECASE)),
        ("eval_execution", re.compile(r'eval\(.*\)', re.IGNORECASE)),
        ("exec_execution", re.compile(r'exec\(.*\)', re.IGNORECASE)),
        ("os_system_execution", re.compile(r'import\s+os;?\s*os\.system', re.IGNORECASE))
    ]

    @classmethod
    def sanitize_external_text(cls, input_text: str) -> str:
        return cls.inspect_external_text(input_text)["sanitized"]

    @classmethod
    def inspect_external_text(cls, input_text: str) -> Dict[str, object]:
        """
        Sanitizes external text (scraped web pages, ad copy, external API inputs)
        to remove indirect prompt injection vectors before passing into agent context.
        """
        if not input_text or not isinstance(input_text, str):
            return {"sanitized": "", "findings": []}

        sanitized = input_text
        findings: List[Dict[str, str]] = []

        for rule_name, pattern in cls.INJECTION_RULES:
            for match in pattern.finditer(input_text):
                findings.append({
                    "rule": rule_name,
                    "match": match.group(0),
                })
            sanitized = pattern.sub('[REDACTED_PROMPT_INJECTION]', sanitized)

        return {"sanitized": sanitized, "findings": findings}
