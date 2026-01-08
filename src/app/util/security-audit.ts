/**
 * Security utility to validate URLs before binding to SVG/MathML attributes
 * Addresses Dependabot Alert #58 (Angular XSS via SVG attributes)
 */
export class SecurityAudit {
  /**
   * Validates that a URL is safe for use in href/xlink:href attributes
   * Blocks javascript:, data:, and other dangerous protocols
   */
  static isSafeUrl(url: string): boolean {
    if (!url || typeof url !== 'string') return false;

    const dangerous = ['javascript:', 'data:', 'vbscript:', 'file:'];
    const lowerUrl = url.trim().toLowerCase();

    return !dangerous.some(protocol => lowerUrl.startsWith(protocol));
  }

  /**
   * Sanitizes a URL for safe use, returns empty string if dangerous
   */
  static sanitizeUrl(url: string): string {
    return this.isSafeUrl(url) ? url : '';
  }
}
