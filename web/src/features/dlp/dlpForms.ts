import type { DlpAction, DlpConfidence, DlpDetector, DlpPolicy, DlpRule, InspectionReason } from '@/api';
import type { DlpDetectorCreate, DlpDetectorUpdate, DlpPolicyUpdate, DlpRuleCreate, DlpRuleUpdate } from '@/hooks/dlp';
import { durationSeconds, normalizeDuration } from '@/lib/durations';

/**
 * The DLP admin forms (#218; FR-38, FR-40, FR-41, FR-45): the trusted domains and the approval timeout, a rule, and a
 * keyword list. Each form keeps the text the admin types and turns it into the contract's body; only what changed is
 * sent, with `expected_version` set to the policy version the page loaded, so two admins can't overwrite each other
 * (`409 dlp_policy_conflict`).
 */

// ---- trusted domains (FR-45) ----

export const MAX_TRUSTED_DOMAINS = 500;

const LABEL = '[\\p{L}\\p{N}](?:[\\p{L}\\p{N}-]{0,61}[\\p{L}\\p{N}])?';
const DOMAIN = new RegExp(`^(?=.{1,253}$)(?:${LABEL}\\.)+${LABEL}$`, 'u');

/** A domain as the API keeps it: trimmed, lowercase, without a trailing dot; `null` if it isn't a domain name. */
export function normalizeDomain(text: string): string | null {
  const domain = text.trim().toLowerCase().replace(/\.$/, '');
  return DOMAIN.test(domain) ? domain : null;
}

export interface DomainsAdded {
  domains: string[];
  /** What was typed that isn't a domain name. */
  invalid: string[];
  /** Domains that would go past 500. */
  overLimit: string[];
}

/** Adds what the admin typed (one domain, or several separated by spaces, commas or lines) to the list. */
export function addDomains(current: readonly string[], input: string): DomainsAdded {
  const domains = [...current];
  const invalid: string[] = [];
  const overLimit: string[] = [];
  for (const part of input.split(/[\s,;]+/).filter(Boolean)) {
    const domain = normalizeDomain(part);
    if (domain === null) invalid.push(part);
    else if (domains.includes(domain)) continue;
    else if (domains.length >= MAX_TRUSTED_DOMAINS) overLimit.push(domain);
    else domains.push(domain);
  }
  return { domains, invalid, overLimit };
}

export function domainChanges(before: readonly string[], after: readonly string[]): { added: string[]; removed: string[] } {
  return {
    added: after.filter((domain) => !before.includes(domain)),
    removed: before.filter((domain) => !after.includes(domain)),
  };
}

// ---- the approval timeout (FR-43) ----

export const MIN_APPROVAL_TIMEOUT = 'PT1H';
export const MAX_APPROVAL_TIMEOUT = 'P7D';
export const APPROVAL_TIMEOUT_CHOICES = ['PT1H', 'PT4H', 'PT12H', 'P1D', 'P2D', 'P3D', 'P7D'] as const;

/** The choices, with the policy's own value when it isn't one of them, shortest first. */
export function approvalTimeoutOptions(current: string): string[] {
  const options: string[] = [...APPROVAL_TIMEOUT_CHOICES];
  const normalized = normalizeDuration(current);
  if (normalized && !options.includes(normalized)) options.push(normalized);
  return options.sort((a, b) => (durationSeconds(a) ?? 0) - (durationSeconds(b) ?? 0));
}

export function isApprovalTimeout(value: string): boolean {
  const seconds = durationSeconds(value);
  return (
    seconds !== null &&
    seconds >= (durationSeconds(MIN_APPROVAL_TIMEOUT) as number) &&
    seconds <= (durationSeconds(MAX_APPROVAL_TIMEOUT) as number)
  );
}

export interface SettingsForm {
  trusted_domains: string[];
  approval_timeout: string;
}

export function settingsFormOf(policy: DlpPolicy): SettingsForm {
  return {
    trusted_domains: [...policy.trusted_domains],
    approval_timeout: normalizeDuration(policy.approval_timeout) ?? policy.approval_timeout,
  };
}

/**
 * The `PATCH /dlp/policy` body: the fields that changed and the version loaded, or `null` when nothing changed or the
 * timeout is out of range. `mode` is never sent: monitor mode is refused until #221.
 */
export function settingsUpdate(policy: DlpPolicy, form: SettingsForm): DlpPolicyUpdate | null {
  if (!isApprovalTimeout(form.approval_timeout)) return null;
  const body: DlpPolicyUpdate = {};
  const { added, removed } = domainChanges(policy.trusted_domains, form.trusted_domains);
  if (added.length > 0 || removed.length > 0) body.trusted_domains = [...form.trusted_domains];
  if (normalizeDuration(form.approval_timeout) !== normalizeDuration(policy.approval_timeout)) {
    body.approval_timeout = form.approval_timeout;
  }
  return Object.keys(body).length === 0 ? null : { ...body, expected_version: policy.version };
}

// ---- rules (FR-40, FR-41) ----

export const RULE_NAME_MAX = 100;
export const THRESHOLD_MAX = 100_000;
export const MAX_RULE_DETECTORS = 64;

/** The conditions the create form offers: `new_domain` rules come with the default policy and are only edited. */
export const CREATABLE_CONDITIONS = ['content', 'not_inspected'] as const;
export const ACTIONS: readonly DlpAction[] = ['allow_and_record', 'warn', 'require_approval', 'block'];
export const CONFIDENCES: readonly DlpConfidence[] = ['low', 'medium', 'high'];
export const REASONS: readonly InspectionReason[] = ['encrypted', 'no_text', 'unsupported_type', 'too_large', 'limit_exceeded', 'parse_error'];

/**
 * A rule as the form holds it. Only `sent` rules, one approver and no 24-hour window are offered: the API refuses
 * the rest with `422 validation_failed` until #221.
 */
export interface RuleForm {
  name: string;
  enabled: boolean;
  condition: DlpRule['condition'];
  detectors: string[];
  min_confidence: DlpConfidence;
  threshold: string;
  reasons: InspectionReason[];
  recipient_scope: DlpRule['recipient_scope'];
  action: DlpAction;
}

export const emptyRuleForm: RuleForm = {
  name: '',
  enabled: true,
  condition: 'content',
  detectors: [],
  min_confidence: 'medium',
  threshold: '1',
  reasons: [],
  recipient_scope: 'any',
  action: 'warn',
};

export function ruleFormOf(rule: DlpRule): RuleForm {
  return {
    name: rule.name,
    enabled: rule.enabled,
    condition: rule.condition,
    detectors: [...rule.detectors],
    min_confidence: rule.min_confidence,
    threshold: String(rule.threshold),
    reasons: [...rule.reasons],
    recipient_scope: rule.recipient_scope,
    action: rule.action,
  };
}

export type RuleField = 'name' | 'detectors' | 'threshold' | 'reasons';
export type RuleProblem = 'name' | 'detectors' | 'tooManyDetectors' | 'threshold' | 'reasons';

/** The threshold as a whole number from 1 to 100,000, or `null`. */
export function thresholdOf(text: string): number | null {
  if (!/^\d+$/.test(text.trim())) return null;
  const value = Number(text.trim());
  return value >= 1 && value <= THRESHOLD_MAX ? value : null;
}

/** What is wrong with the form, by field; empty when it can be saved. */
export function ruleProblems(form: RuleForm): Partial<Record<RuleField, RuleProblem>> {
  const problems: Partial<Record<RuleField, RuleProblem>> = {};
  const name = form.name.trim();
  if (name.length === 0 || name.length > RULE_NAME_MAX) problems.name = 'name';
  if (form.condition === 'content') {
    if (form.detectors.length === 0) problems.detectors = 'detectors';
    else if (form.detectors.length > MAX_RULE_DETECTORS) problems.detectors = 'tooManyDetectors';
    if (thresholdOf(form.threshold) === null) problems.threshold = 'threshold';
  }
  if (form.condition === 'not_inspected' && form.reasons.length === 0) problems.reasons = 'reasons';
  return problems;
}

/** The `createDlpRule` body, or `null` while the form has problems. Only the condition's own fields are sent. */
export function ruleCreateBody(form: RuleForm, version: number): DlpRuleCreate | null {
  if (Object.keys(ruleProblems(form)).length > 0) return null;
  const body: DlpRuleCreate = {
    expected_version: version,
    name: form.name.trim(),
    enabled: form.enabled,
    direction: 'sent',
    condition: form.condition,
    recipient_scope: form.recipient_scope,
    action: form.action,
  };
  if (form.condition === 'content') {
    body.detectors = [...form.detectors];
    body.min_confidence = form.min_confidence;
    body.threshold = thresholdOf(form.threshold) as number;
  }
  if (form.condition === 'not_inspected') body.reasons = [...form.reasons];
  return body;
}

const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((item) => b.includes(item));

/** The fields of a rule the form changed, in the order the confirmation lists them. */
export type RuleChange = 'name' | 'enabled' | 'detectors' | 'min_confidence' | 'threshold' | 'reasons' | 'recipient_scope' | 'action';

/**
 * The `updateDlpRule` body: only what changed, and the version loaded; `null` while the form has problems, and
 * `{ changes: [] }` when nothing changed. The condition itself is never changed: a rule keeps its kind.
 */
export function ruleUpdate(rule: DlpRule, form: RuleForm, version: number): { body: DlpRuleUpdate; changes: RuleChange[] } | null {
  if (Object.keys(ruleProblems({ ...form, condition: rule.condition })).length > 0) return null;
  const body: DlpRuleUpdate = {};
  const changes: RuleChange[] = [];
  const name = form.name.trim();
  if (name !== rule.name) {
    body.name = name;
    changes.push('name');
  }
  if (form.enabled !== rule.enabled) {
    body.enabled = form.enabled;
    changes.push('enabled');
  }
  if (rule.condition === 'content') {
    if (!sameSet(form.detectors, rule.detectors)) {
      body.detectors = [...form.detectors];
      changes.push('detectors');
    }
    if (form.min_confidence !== rule.min_confidence) {
      body.min_confidence = form.min_confidence;
      changes.push('min_confidence');
    }
    const threshold = thresholdOf(form.threshold) as number;
    if (threshold !== rule.threshold) {
      body.threshold = threshold;
      changes.push('threshold');
    }
  }
  if (rule.condition === 'not_inspected' && !sameSet(form.reasons, rule.reasons)) {
    body.reasons = [...form.reasons];
    changes.push('reasons');
  }
  if (form.recipient_scope !== rule.recipient_scope) {
    body.recipient_scope = form.recipient_scope;
    changes.push('recipient_scope');
  }
  if (form.action !== rule.action) {
    body.action = form.action;
    changes.push('action');
  }
  return { body: changes.length > 0 ? { ...body, expected_version: version } : {}, changes };
}

/** The keyword lists a rule can name: `custom:<id>` of the tenant's own `keywords` detectors. */
export function keywordLists(detectors: readonly DlpDetector[]): DlpDetector[] {
  return detectors.filter((detector) => detector.kind === 'keywords');
}

export function builtInDetectors(detectors: readonly DlpDetector[]): DlpDetector[] {
  return detectors.filter((detector) => detector.kind === 'built_in');
}

// ---- keyword lists (FR-38) ----

export const MAX_TERMS = 1000;
export const TERM_MAX = 100;
export const DETECTOR_NAME_MAX = 100;

export interface TermsParsed {
  terms: string[];
  /** Terms longer than 100 characters, as typed. */
  tooLong: string[];
  /** How many lines repeated a term already listed. */
  duplicates: number;
}

/** One term per line: trimmed, blank lines left out, each term once, in the order typed. */
export function parseTerms(text: string): TermsParsed {
  const terms: string[] = [];
  const tooLong: string[] = [];
  let duplicates = 0;
  for (const line of text.split(/\r?\n/)) {
    const term = line.trim();
    if (!term) continue;
    if ([...term].length > TERM_MAX) tooLong.push(term);
    else if (terms.includes(term)) duplicates += 1;
    else terms.push(term);
  }
  return { terms, tooLong, duplicates };
}

export type KeywordProblem = 'name' | 'noTerms' | 'tooManyTerms' | 'termTooLong';

export interface KeywordForm {
  name: string;
  terms: string;
}

export function keywordFormOf(detector: DlpDetector): KeywordForm {
  return { name: detector.name, terms: (detector.keywords ?? []).join('\n') };
}

export function keywordProblems(form: KeywordForm): Partial<Record<'name' | 'terms', KeywordProblem>> {
  const problems: Partial<Record<'name' | 'terms', KeywordProblem>> = {};
  const name = form.name.trim();
  if (name.length === 0 || name.length > DETECTOR_NAME_MAX) problems.name = 'name';
  const { terms, tooLong } = parseTerms(form.terms);
  if (tooLong.length > 0) problems.terms = 'termTooLong';
  else if (terms.length === 0) problems.terms = 'noTerms';
  else if (terms.length > MAX_TERMS) problems.terms = 'tooManyTerms';
  return problems;
}

export function keywordCreateBody(form: KeywordForm, version: number): DlpDetectorCreate | null {
  if (Object.keys(keywordProblems(form)).length > 0) return null;
  return { expected_version: version, name: form.name.trim(), kind: 'keywords', keywords: parseTerms(form.terms).terms };
}

export type KeywordChange = 'name' | 'terms';

/** The `updateDlpDetector` body: the name and the terms when they changed, and the version loaded. */
export function keywordUpdate(
  detector: DlpDetector,
  form: KeywordForm,
  version: number,
): { body: DlpDetectorUpdate; changes: KeywordChange[]; added: number; removed: number } | null {
  if (Object.keys(keywordProblems(form)).length > 0) return null;
  const body: DlpDetectorUpdate = {};
  const changes: KeywordChange[] = [];
  const name = form.name.trim();
  if (name !== detector.name) {
    body.name = name;
    changes.push('name');
  }
  const before = detector.keywords ?? [];
  const after = parseTerms(form.terms).terms;
  const added = after.filter((term) => !before.includes(term)).length;
  const removed = before.filter((term) => !after.includes(term)).length;
  if (added > 0 || removed > 0 || after.join('\n') !== before.join('\n')) {
    body.keywords = after;
    changes.push('terms');
  }
  return { body: changes.length > 0 ? { ...body, expected_version: version } : {}, changes, added, removed };
}

/** A detector ID inside a route: `custom:<uuid>` keeps its colon in the path segment (`fillPath` encodes it). */
export function detectorRouteId(id: string): string {
  return encodeURIComponent(id);
}
