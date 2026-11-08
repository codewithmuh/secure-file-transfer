import { describe, expect, it } from 'vitest';
import {
  addDays,
  barPercent,
  countRows,
  dailySeries,
  localDay,
  medianParts,
  outcomeTotals,
  presetRange,
  RANGE_MAX_DAYS,
  rangeDays,
  rangeProblem,
  rangeQuery,
} from './reports';

/** Local midnight of a day, as the picker means it. */
const midnight = (day: string) => {
  const [year, month, date] = day.split('-').map(Number) as [number, number, number];
  return new Date(year, month - 1, date);
};

describe('the report range (#222; FR-55)', () => {
  it('offers the last 7, 30 and 90 days, today included', () => {
    const today = new Date(2026, 10, 8, 15, 30);
    expect(presetRange(7, today)).toEqual({ from: '2026-11-02', to: '2026-11-08' });
    expect(rangeDays(presetRange(30, today))).toBe(30);
    expect(rangeDays(presetRange(90, today))).toBe(90);
    expect(addDays('2026-03-01', -1)).toBe('2026-02-28');
    expect(localDay(today)).toBe('2026-11-08');
  });

  it('refuses a missing day, an end before the start and more than 92 days, as the API does', () => {
    expect(rangeProblem({ from: '', to: '2026-11-08' })).toBe('missing');
    expect(rangeProblem({ from: '2026-02-30', to: '2026-03-01' })).toBe('missing');
    expect(rangeProblem({ from: '2026-11-08', to: '2026-11-07' })).toBe('order');
    expect(rangeProblem({ from: '2026-11-08', to: '2026-11-08' })).toBeNull();
    const longest = { from: addDays('2026-11-08', -(RANGE_MAX_DAYS - 1)), to: '2026-11-08' };
    expect(rangeDays(longest)).toBe(RANGE_MAX_DAYS);
    expect(rangeProblem(longest)).toBeNull();
    expect(rangeProblem({ ...longest, from: addDays(longest.from, -1) })).toBe('tooLong');
  });

  it('asks from the first day\'s midnight to the midnight after the last, never past now', () => {
    const range = { from: '2026-10-01', to: '2026-10-07' };
    const later = midnight('2026-11-01').getTime();
    expect(rangeQuery(range, later)).toEqual({
      from: midnight('2026-10-01').toISOString(),
      to: midnight('2026-10-08').toISOString(),
    });
    const now = midnight('2026-10-07').getTime() + 3_600_000 + 500;
    expect(rangeQuery(range, now)?.to).toBe(new Date(midnight('2026-10-07').getTime() + 3_600_000).toISOString());
    expect(rangeQuery({ from: '2026-10-07', to: '2026-10-01' }, later)).toBeNull();
  });
});

describe('the report charts (#222)', () => {
  const report = {
    from: midnight('2026-11-01').toISOString(),
    to: midnight('2026-11-05').toISOString(),
    decisions_by_outcome: [
      { key: 'warn', count: 3 },
      { key: 'block', count: 1 },
      { key: 'something_new', count: 9 },
    ],
    decisions_by_day: [
      { date: '2026-11-03', by_outcome: [{ key: 'block', count: 1 }] },
      {
        date: '2026-11-01',
        by_outcome: [
          { key: 'warn', count: 2 },
          { key: 'none', count: 4 },
        ],
      },
    ],
  };

  it('totals every outcome, unknown keys left out', () => {
    expect(outcomeTotals(report)).toEqual({ none: 0, allow_and_record: 0, warn: 3, require_approval: 0, block: 1 });
  });

  it('gives one entry per day of the range, days without decisions at zero', () => {
    const series = dailySeries(report);
    expect(series.map((day) => day.date)).toEqual(['2026-11-01', '2026-11-02', '2026-11-03', '2026-11-04']);
    expect(series[0]).toMatchObject({ total: 6, counts: { warn: 2, none: 4 } });
    expect(series[1]?.total).toBe(0);
    expect(series[2]?.counts.block).toBe(1);
  });

  it('widens to a day the report gives outside the range', () => {
    const series = dailySeries({ ...report, decisions_by_day: [{ date: '2026-10-31', by_outcome: [{ key: 'warn', count: 1 }] }] });
    expect(series[0]?.date).toBe('2026-10-31');
    expect(series).toHaveLength(5);
  });

  it('labels and sorts a breakdown, the largest first, and draws a sliver for small counts', () => {
    const names: Record<string, string> = { a: 'Bravo', b: 'Alpha' };
    expect(
      countRows(
        [
          { key: 'a', count: 2 },
          { key: 'b', count: 2 },
          { key: 'c', count: 7 },
        ],
        (key) => names[key] ?? `rule ${key}`,
      ),
    ).toEqual([
      { key: 'c', label: 'rule c', count: 7 },
      { key: 'b', label: 'Alpha', count: 2 },
      { key: 'a', label: 'Bravo', count: 2 },
    ]);
    expect(barPercent(7, 7)).toBe(100);
    expect(barPercent(1, 1000)).toBe(2);
    expect(barPercent(0, 10)).toBe(0);
  });

  it('words a median decision time', () => {
    expect(medianParts(null)).toEqual({ unit: 'none', count: 0 });
    expect(medianParts(30)).toEqual({ unit: 'underMinute', count: 0 });
    expect(medianParts(150)).toEqual({ unit: 'minutes', count: 3 });
    expect(medianParts(3 * 3600 + 600)).toEqual({ unit: 'hours', count: 3 });
    expect(medianParts(3 * 86_400)).toEqual({ unit: 'days', count: 3 });
  });
});
