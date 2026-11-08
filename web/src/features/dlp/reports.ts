import type { DlpOutcome, Schema } from '@/api';
import type { DlpRange, DlpReport } from '@/hooks/dlp';

/**
 * The DLP report page's logic (#222; FR-55, UC-4), apart from React so it can be tested on its own: the range picker
 * (local calendar days, at most 92 as the API allows), the series the charts draw, the rows of each breakdown, and
 * how a decision time reads.
 */

export type DlpCount = Schema<'DlpCount'>;

export const RANGE_MAX_DAYS = 92;
export const RANGE_PRESETS = [7, 30, 90] as const;
export const DEFAULT_RANGE_DAYS = 30;
const DAY_MS = 86_400_000;

/** Outcomes from the least to the strictest: the order of the stacks, the legend and the filter. */
export const OUTCOMES: readonly DlpOutcome[] = ['none', 'allow_and_record', 'warn', 'require_approval', 'block'];

/** A range as the picker holds it: two `YYYY-MM-DD` local days, both included. */
export interface DayRange {
  from: string;
  to: string;
}

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** A local date as `YYYY-MM-DD`. */
export function localDay(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** Local midnight of a `YYYY-MM-DD` day, or `null` when it isn't one. */
function midnight(day: string): Date | null {
  const match = DAY.exec(day);
  if (!match) return null;
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  return localDay(date) === day ? date : null;
}

/** The day `count` days after (or before) `day`, by the calendar, so a daylight saving change doesn't move it. */
export function addDays(day: string, count: number): string {
  const date = midnight(day);
  if (!date) return day;
  date.setDate(date.getDate() + count);
  return localDay(date);
}

/** The last `days` days, today included. */
export function presetRange(days: number, today: Date): DayRange {
  const to = localDay(today);
  return { from: addDays(to, -(days - 1)), to };
}

/** How many days the range covers, both ends included; `null` when a day isn't valid. */
export function rangeDays(range: DayRange): number | null {
  const from = midnight(range.from);
  const to = midnight(range.to);
  if (!from || !to) return null;
  return Math.round((to.getTime() - from.getTime()) / DAY_MS) + 1;
}

export type RangeProblem = 'missing' | 'order' | 'tooLong';

/** What is wrong with the range: a day missing or invalid, the end before the start, or more than 92 days. */
export function rangeProblem(range: DayRange): RangeProblem | null {
  const days = rangeDays(range);
  if (days === null) return 'missing';
  if (days < 1) return 'order';
  if (days > RANGE_MAX_DAYS) return 'tooLong';
  return null;
}

/**
 * The range as the API takes it: from the first day's local midnight (inclusive) to the midnight after the last day
 * (exclusive), but never past `now`, so a range ending today asks up to now, in whole seconds: the audit log's filter
 * takes the same times to the second, so its export counts the same decisions. `null` while the range has a problem.
 */
export function rangeQuery(range: DayRange, now: number): DlpRange | null {
  if (rangeProblem(range) !== null) return null;
  const from = midnight(range.from) as Date;
  const end = midnight(addDays(range.to, 1)) as Date;
  const second = Math.floor(now / 1000) * 1000;
  const to = Math.min(end.getTime(), Math.max(second, from.getTime() + 1000));
  return { from: from.toISOString(), to: new Date(to).toISOString() };
}

// ---- the charts ----

export type OutcomeCounts = Record<DlpOutcome, number>;

const noCounts = (): OutcomeCounts => ({ none: 0, allow_and_record: 0, warn: 0, require_approval: 0, block: 0 });

function addCounts(target: OutcomeCounts, rows: readonly DlpCount[]): void {
  for (const row of rows) if ((OUTCOMES as readonly string[]).includes(row.key)) target[row.key as DlpOutcome] += row.count;
}

/** Decisions by outcome over the whole range, every outcome present. */
export function outcomeTotals(report: Pick<DlpReport, 'decisions_by_outcome'>): OutcomeCounts {
  const totals = noCounts();
  addCounts(totals, report.decisions_by_outcome);
  return totals;
}

export interface DaySeries {
  date: string;
  counts: OutcomeCounts;
  total: number;
}

/** The most days a series holds: 92 and a day either side for time zones. */
const MAX_SERIES_DAYS = RANGE_MAX_DAYS + 2;

/**
 * One entry per day of the range, days with no decisions at zero, so the bars keep the calendar's spacing. The range
 * is the report's own (`from`, and the day before `to`) in local days, widened to any day the report gives.
 */
export function dailySeries(report: Pick<DlpReport, 'from' | 'to' | 'decisions_by_day'>): DaySeries[] {
  const byDate = new Map<string, OutcomeCounts>();
  for (const day of report.decisions_by_day) {
    const counts = byDate.get(day.date) ?? noCounts();
    addCounts(counts, day.by_outcome);
    byDate.set(day.date, counts);
  }
  const given = [...byDate.keys()].sort();
  const from = localDay(new Date(report.from));
  const last = localDay(new Date(Date.parse(report.to) - 1));
  const first = given[0] !== undefined && given[0] < from ? given[0] : from;
  const end = given.length > 0 && (given[given.length - 1] as string) > last ? (given[given.length - 1] as string) : last;
  const series: DaySeries[] = [];
  for (let date = first; date <= end && series.length < MAX_SERIES_DAYS; date = addDays(date, 1)) {
    const counts = byDate.get(date) ?? noCounts();
    series.push({ date, counts, total: OUTCOMES.reduce((sum, outcome) => sum + counts[outcome], 0) });
  }
  return series;
}

export interface CountRow {
  key: string;
  label: string;
  count: number;
}

/** A breakdown's rows with their labels, the largest first (then by label), for a bar list or a table. */
export function countRows(rows: readonly DlpCount[], label: (key: string) => string): CountRow[] {
  return rows
    .map((row) => ({ key: row.key, label: label(row.key), count: row.count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

/** A bar's share of the largest, in percent, at least a sliver for any count above zero. */
export function barPercent(count: number, max: number): number {
  if (count <= 0 || max <= 0) return 0;
  return Math.max(2, Math.round((count / max) * 100));
}

/** A median decision time as the page words it: under a minute, minutes, hours or days; `none` without decisions. */
export function medianParts(seconds: number | null): { unit: 'none' | 'underMinute' | 'minutes' | 'hours' | 'days'; count: number } {
  if (seconds === null) return { unit: 'none', count: 0 };
  if (seconds < 60) return { unit: 'underMinute', count: 0 };
  if (seconds < 2 * 3600) return { unit: 'minutes', count: Math.round(seconds / 60) };
  if (seconds < 2 * 86_400) return { unit: 'hours', count: Math.round(seconds / 3600) };
  return { unit: 'days', count: Math.round(seconds / 86_400) };
}
