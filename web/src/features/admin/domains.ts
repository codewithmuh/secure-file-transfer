/**
 * The tenant's allowed and blocked recipient domains (#217; FR-24, FR-45): what the policy page accepts before it
 * sends a list. The service decides in the end (lowercase, IDNA-normalised, a domain covers its subdomains, blocked
 * wins over allowed, an empty allowed list means any domain); the page checks the same shape so an admin sees a
 * mistake by its input, not after saving.
 */

/** The contract's `maxItems` for each list. */
export const MAX_DOMAINS = 500;

export type DomainProblem = 'invalid' | 'duplicate' | 'tooMany';

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * A domain as the service stores it: trimmed, lower case, without a trailing dot, an internationalised name in its
 * ASCII (punycode) form; `null` when it isn't a domain name of at least two labels.
 */
export function normalizeDomain(input: string): string | null {
  let value = input.trim().toLowerCase().replace(/\.$/, '');
  if (value.startsWith('@')) value = value.slice(1); // "@example.com" is how people often write a domain
  if (value === '' || /[\s/:@?#[\]\\]/.test(value)) return null;
  let ascii: string;
  try {
    // The URL parser applies IDNA (UTS 46): "例え.jp" becomes "xn--r8jz45g.jp".
    ascii = new URL(`http://${value}/`).hostname;
  } catch {
    return null;
  }
  if (ascii.length > 253) return null;
  const labels = ascii.split('.');
  if (labels.length < 2 || !labels.every((label) => LABEL.test(label))) return null;
  if (/^\d+$/.test(labels[labels.length - 1] as string)) return null; // an IPv4 address, not a domain
  return ascii;
}

/** Adds `input` to `list`, or says why it can't. */
export function addDomain(list: readonly string[], input: string): { list: string[] } | { problem: DomainProblem } {
  const domain = normalizeDomain(input);
  if (domain === null) return { problem: 'invalid' };
  if (list.includes(domain)) return { problem: 'duplicate' };
  if (list.length >= MAX_DOMAINS) return { problem: 'tooMany' };
  return { list: [...list, domain] };
}

export function removeDomain(list: readonly string[], domain: string): string[] {
  return list.filter((entry) => entry !== domain);
}

/** Whether two lists hold the same domains, in any order. */
export function sameDomains(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((entry) => set.has(entry));
}

/** Domains in both lists: allowed and blocked at once, where blocked wins. The page warns about them. */
export function overlapping(allowed: readonly string[], blocked: readonly string[]): string[] {
  const set = new Set(blocked);
  return allowed.filter((domain) => set.has(domain));
}
