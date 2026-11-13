import { describe, expect, it } from 'vitest';
import { renderToString } from 'react-dom/server';
import { Select } from './Select';

const OPTIONS = [
  { value: 'P1D', label: '1 day' },
  { value: 'P7D', label: '7 days' },
];

/** Every `.tsx` file of the app but the tests, as text (Vite's glob, so no Node types are needed). */
const SOURCES = import.meta.glob<string>(['/src/**/*.tsx', '!/src/**/*.test.tsx'], {
  query: '?raw',
  import: 'default',
  eager: true,
});

describe('Select (#169)', () => {
  it('ties each label to its own select, with no ID shared by two on one page', () => {
    const html = renderToString(
      <>
        <Select label="Expiry" options={OPTIONS} hint="How long the link works." />
        <Select label="Longest expiry" options={OPTIONS} error="Choose one." />
      </>,
    );
    const labels = [...html.matchAll(/<label for="([^"]+)"/g)].map((match) => match[1]);
    const selects = [...html.matchAll(/<select id="([^"]+)"/g)].map((match) => match[1]);
    expect(labels).toHaveLength(2);
    expect(new Set(labels).size).toBe(2);
    expect(selects).toEqual(labels);
    expect(html).toContain(`aria-describedby="${labels[0]}-hint"`);
    expect(html).toContain(`aria-describedby="${labels[1]}-error"`);
    expect(html).toContain('aria-invalid="true"');
  });

  it('keeps a hidden label for screen readers, where a column header names the select on screen', () => {
    const html = renderToString(<Select label="Role for staff" hideLabel options={OPTIONS} />);
    expect(html).toMatch(/<label for="[^"]+" class="sr-only">Role for staff<\/label>/);
  });

  it('is the only select in the app: no page writes its own, with a hand-made ID', () => {
    const files = Object.entries(SOURCES);
    expect(files.length).toBeGreaterThan(20);
    const own = files
      .filter(([path]) => !path.endsWith('/components/ui/Select.tsx'))
      .filter(([, code]) => /<select\b/.test(code))
      .map(([path]) => path);
    expect(own).toEqual([]);
  });
});
