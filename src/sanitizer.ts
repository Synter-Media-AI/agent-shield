export class SynterPromptSanitizer {
  private static readonly INJECTION_PATTERNS = [
    /system:\s*override/gi,
    /ignore\s+(all\s+)?previous\s+instructions/gi,
    /you\s+are\s+now\s+a/gi,
    /<system_reminder>/gi,
    /<\/system_reminder>/gi,
    /eval\(.*\)/gi,
    /exec\(.*\)/gi,
    /import\s+os;?\s*os\.system/gi
  ];

  /**
   * Sanitizes external text (scraped web pages, ad copy, external API inputs)
   * to remove indirect prompt injection vectors before passing into agent context.
   */
  public static sanitizeExternalText(input: string): string {
    if (!input || typeof input !== 'string') return '';

    let sanitized = input;
    for (const pattern of SynterPromptSanitizer.INJECTION_PATTERNS) {
      sanitized = sanitized.replace(pattern, '[REDACTED_PROMPT_INJECTION]');
    }

    return sanitized;
  }
}
