import { describe, expect, it } from 'vitest';
import { addDomain, MAX_DOMAINS, normalizeDomain, overlapping, removeDomain, sameDomains } from './domains';

describe('recipient domains (#217, FR-24)', () => {
  it('normalises a domain as the service stores it', () => {
    expect(normalizeDomain(' Example.COM. ')).toBe('example.com');
    expect(normalizeDomain('@partner.co.jp')).toBe('partner.co.jp');
    expect(normalizeDomain('mail.sub.example.org')).toBe('mail.sub.example.org');
  });

  it('turns an internationalised domain into its IDNA form', () => {
    expect(normalizeDomain('例え.jp')).toBe('xn--r8jz45g.jp');
    expect(normalizeDomain('BÜCHER.example')).toBe('xn--bcher-kva.example');
  });

  it('refuses what isn\'t a domain', () => {
    for (const bad of ['', 'localhost', 'a b.com', 'user@example.com', 'https://example.com', '-bad.com', 'bad-.com', '192.0.2.1', 'x'.repeat(64) + '.com', 'example.com/path', 'a..b.com']) {
      expect(normalizeDomain(bad), bad).toBeNull();
    }
  });

  it('adds a domain once, and at most 500', () => {
    expect(addDomain([], 'Example.com')).toEqual({ list: ['example.com'] });
    expect(addDomain(['example.com'], 'EXAMPLE.com')).toEqual({ problem: 'duplicate' });
    expect(addDomain([], 'nope')).toEqual({ problem: 'invalid' });
    const full = Array.from({ length: MAX_DOMAINS }, (_, i) => `d${i}.example`);
    expect(addDomain(full, 'one-more.example')).toEqual({ problem: 'tooMany' });
  });

  it('removes, compares in any order, and finds domains in both lists', () => {
    expect(removeDomain(['a.example', 'b.example'], 'a.example')).toEqual(['b.example']);
    expect(sameDomains(['a.example', 'b.example'], ['b.example', 'a.example'])).toBe(true);
    expect(sameDomains(['a.example'], ['a.example', 'b.example'])).toBe(false);
    expect(overlapping(['a.example', 'b.example'], ['b.example'])).toEqual(['b.example']);
  });
});
