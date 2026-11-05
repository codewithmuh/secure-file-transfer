import { describe, expect, it } from 'vitest';
import { LANGUAGES, preferredLanguage, resources } from './i18n';

/**
 * The translation check (FR-33, #110): every language has the same keys, no value is empty, and each key names the
 * same `{{placeholders}}` in every language. A missing or empty key fails CI here, not on a Japanese recipient's page.
 */

type Tree = { [key: string]: unknown };

// i18next's plural suffixes. English needs `_one` and `_other`, Japanese only `_other`, so they compare as one key.
const PLURAL_SUFFIX = /_(zero|one|two|few|many|other)$/;
const PLACEHOLDER = /\{\{\s*([\w.]+)\s*\}\}/g;

/** Every leaf as `dotted.key → value`, plural forms under their base key. Problems are added to `problems`. */
function leaves(tree: Tree, problems: string[], prefix = ''): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const [name, value] of Object.entries(tree)) {
    const key = prefix ? `${prefix}.${name}` : name;
    if (typeof value === 'object' && value !== null) {
      for (const [inner, values] of leaves(value as Tree, problems, key)) found.set(inner, values);
    } else if (typeof value !== 'string' || value.trim() === '') {
      problems.push(`${key} is empty`);
    } else {
      const base = key.replace(PLURAL_SUFFIX, '');
      found.set(base, [...(found.get(base) ?? []), value]);
    }
  }
  return found;
}

function placeholders(values: string[]): string {
  const names = new Set(values.flatMap((value) => [...value.matchAll(PLACEHOLDER)].map((match) => match[1])));
  return [...names].sort().join(', ');
}

/** What is wrong with a set of translations, as one line per problem; empty when they agree. */
function translationProblems(languages: Record<string, Tree>): string[] {
  const problems: string[] = [];
  const byLanguage = Object.entries(languages).map(([language, tree]) => {
    const languageProblems: string[] = [];
    const found = leaves(tree, languageProblems);
    problems.push(...languageProblems.map((problem) => `${language}: ${problem}`));
    return { language, found };
  });
  const allKeys = new Set(byLanguage.flatMap(({ found }) => [...found.keys()]));
  for (const key of [...allKeys].sort()) {
    const present = byLanguage.filter(({ found }) => found.has(key));
    for (const { language } of byLanguage.filter(({ found }) => !found.has(key))) {
      problems.push(`${language}: ${key} is missing`);
    }
    const names = new Set(present.map(({ found }) => placeholders(found.get(key) ?? [])));
    if (names.size > 1) {
      problems.push(
        `${key} names different placeholders: ${present
          .map(({ language, found }) => `${language} [${placeholders(found.get(key) ?? [])}]`)
          .join(', ')}`,
      );
    }
  }
  return problems;
}

describe('translations (FR-33)', () => {
  it('English and Japanese have the same keys, no empty values and the same placeholders', () => {
    const trees = Object.fromEntries(LANGUAGES.map((language) => [language, resources[language].translation]));
    expect(LANGUAGES).toEqual(['en', 'ja']);
    expect(translationProblems(trees)).toEqual([]);
  });
});

describe('translationProblems', () => {
  it('finds a key missing in one language', () => {
    expect(translationProblems({ en: { a: { b: 'B', c: 'C' } }, ja: { a: { b: 'ビー' } } })).toEqual([
      'ja: a.c is missing',
    ]);
  });

  it('finds empty and blank values', () => {
    expect(translationProblems({ en: { a: '', b: 'B' }, ja: { a: 'エー', b: '  ' } })).toEqual([
      'en: a is empty',
      'ja: b is empty',
      'en: a is missing',
      'ja: b is missing',
    ]);
  });

  it('treats plural forms as one key, as i18next does', () => {
    expect(
      translationProblems({ en: { n: '{{count}} file', n_other: '{{count}} files' }, ja: { n: '{{count}}件' } }),
    ).toEqual([]);
  });

  it('finds a placeholder one language lacks', () => {
    expect(translationProblems({ en: { sent: 'Sent to {{email}}' }, ja: { sent: '送信しました' } })).toEqual([
      'sent names different placeholders: en [email], ja []',
    ]);
  });
});

describe('preferredLanguage', () => {
  it.each([
    [['ja-JP', 'en-US'], 'ja'],
    [['fr-FR', 'JA'], 'ja'],
    [['en-GB'], 'en'],
    [['de-DE'], 'en'],
    [[], 'en'],
  ])('picks %j as %s', (preferred, expected) => {
    expect(preferredLanguage(preferred)).toBe(expected);
  });
});
