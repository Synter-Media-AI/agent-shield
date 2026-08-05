export interface PromptInjectionFinding {
  rule: string;
  match: string;
}

export interface PromptSanitizationResult {
  sanitized: string;
  findings: PromptInjectionFinding[];
}

interface PromptInjectionRule {
  name: string;
  pattern: RegExp;
}

export class SynterPromptSanitizer {
  private static readonly INJECTION_RULES: PromptInjectionRule[] = [
    { name: 'system_override', pattern: /system:\s*override/gi },
    { name: 'ignore_previous_instructions', pattern: /ignore\s+(all\s+)?previous\s+instructions/gi },
    { name: 'role_reassignment', pattern: /you\s+are\s+now\s+a/gi },
    { name: 'system_reminder_tag', pattern: /<system_reminder>/gi },
    { name: 'system_reminder_close_tag', pattern: /<\/system_reminder>/gi },
    { name: 'eval_execution', pattern: /eval\(.*\)/gi },
    { name: 'exec_execution', pattern: /exec\(.*\)/gi },
    { name: 'os_system_execution', pattern: /import\s+os;?\s*os\.system/gi }
  ];

  /**
   * Sanitizes external text (scraped web pages, ad copy, external API inputs)
   * to remove indirect prompt injection vectors before passing into agent context.
   */
  public static sanitizeExternalText(input: string): string {
    return SynterPromptSanitizer.inspectExternalText(input).sanitized;
  }

  /**
   * Reports the prompt-injection-like patterns found in external text and
   * returns the redacted replacement text used by the compiler/runtime.
   */
  public static inspectExternalText(input: string): PromptSanitizationResult {
    if (!input || typeof input !== 'string') {
      return { sanitized: '', findings: [] };
    }

    let sanitized = input;
    const findings: PromptInjectionFinding[] = [];

    for (const { name, pattern } of SynterPromptSanitizer.INJECTION_RULES) {
      const matches = input.match(pattern) ?? [];
      for (const match of matches) {
        findings.push({ rule: name, match });
      }
      sanitized = sanitized.replace(pattern, '[REDACTED_PROMPT_INJECTION]');
    }

    return { sanitized, findings };
  }
}
