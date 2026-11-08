import type { DlpAction, DlpConfidence, DlpDetector, DlpPolicy, DlpRule, InspectionReason, Schema } from '@/api';
import type { DlpDetectorCreate, DlpDetectorUpdate, DlpPolicyUpdate, DlpRuleCreate, DlpRuleUpdate } from '@/hooks/dlp';
import { durationSeconds, normalizeDuration } from '@/lib/durations';

/**
 * The DLP admin forms (#218, #221; FR-38 to FR-41, FR-44, FR-45, FR-49, FR-51, FR-52): the mode, the trusted domains
 * and the approval timeout, a rule, a keyword list and a pattern. Each form keeps the text the admin types and turns it into the contract's body; only what changed is
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

export type DlpMode = Schema<'DlpMode'>;
export const MODES: readonly DlpMode[] = ['enforce', 'monitor'];

export interface SettingsForm {
  /** `monitor` records every decision and sends every transfer; no received file is blocked (FR-52). */
  mode: DlpMode;
  trusted_domains: string[];
  approval_timeout: string;
}

export function settingsFormOf(policy: DlpPolicy): SettingsForm {
  return {
    mode: policy.mode,
    trusted_domains: [...policy.trusted_domains],
    approval_timeout: normalizeDuration(policy.approval_timeout) ?? policy.approval_timeout,
  };
}

/**
 * The `PATCH /dlp/policy` body: the fields that changed and the version loaded, or `null` when nothing changed or the
 * timeout is out of range. The mode is sent only when it changed (#221).
 */
export function settingsUpdate(policy: DlpPolicy, form: SettingsForm): DlpPolicyUpdate | null {
  if (!isApprovalTimeout(form.approval_timeout)) return null;
  const body: DlpPolicyUpdate = {};
  if (form.mode !== policy.mode) body.mode = form.mode;
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
/** A rule for received files only records or blocks (FR-51): there is no sender to warn or to ask for approval. */
export const RECEIVED_ACTIONS: readonly DlpAction[] = ['allow_and_record', 'block'];
export type RuleDirection = DlpRule['direction'];
export const DIRECTIONS: readonly RuleDirection[] = ['sent', 'received'];

/** The actions a rule for these files may take. */
export function actionsFor(direction: RuleDirection): readonly DlpAction[] {
  return direction === 'received' ? RECEIVED_ACTIONS : ACTIONS;
}
export const CONFIDENCES: readonly DlpConfidence[] = ['low', 'medium', 'high'];
export const REASONS: readonly InspectionReason[] = ['encrypted', 'no_text', 'unsupported_type', 'too_large', 'limit_exceeded', 'parse_error'];

/**
 * A rule as the form holds it (#221): for sent or received files (chosen on create only), and for sent files the
 * sender's last 24 hours (FR-49) and two approvers (FR-44). The fields that don't apply to the direction, condition
 * or action are kept as typed but never sent.
 */
export interface RuleForm {
  name: string;
  enabled: boolean;
  direction: RuleDirection;
  condition: DlpRule['condition'];
  detectors: string[];
  min_confidence: DlpConfidence;
  threshold: string;
  reasons: InspectionReason[];
  recipient_scope: DlpRule['recipient_scope'];
  action: DlpAction;
  /** FR-49: a content rule for sent files also counts the sender's matches in the last 24 hours. */
  include_sender_24h: boolean;
  /** FR-44: how many different approvers a `require_approval` rule needs, 1 or 2. */
  approvals_required: 1 | 2;
}

export const emptyRuleForm: RuleForm = {
  name: '',
  enabled: true,
  direction: 'sent',
  condition: 'content',
  detectors: [],
  min_confidence: 'medium',
  threshold: '1',
  reasons: [],
  recipient_scope: 'any',
  action: 'warn',
  include_sender_24h: false,
  approvals_required: 1,
};

export function ruleFormOf(rule: DlpRule): RuleForm {
  return {
    name: rule.name,
    enabled: rule.enabled,
    direction: rule.direction,
    condition: rule.condition,
    detectors: [...rule.detectors],
    min_confidence: rule.min_confidence,
    threshold: String(rule.threshold),
    reasons: [...rule.reasons],
    recipient_scope: rule.recipient_scope,
    action: rule.action,
    include_sender_24h: rule.include_sender_24h,
    approvals_required: rule.approvals_required === 2 ? 2 : 1,
  };
}

/**
 * The form for another direction (create only): a rule for received files takes no recipients and no 24-hour window,
 * and only records or blocks, so an action it can't take becomes "Block".
 */
export function withDirection(form: RuleForm, direction: RuleDirection): RuleForm {
  if (direction === 'sent') return { ...form, direction };
  return {
    ...form,
    direction,
    recipient_scope: 'any',
    include_sender_24h: false,
    approvals_required: 1,
    action: RECEIVED_ACTIONS.includes(form.action) ? form.action : 'block',
  };
}

/** Whether the 24-hour option applies: a content rule for sent files (FR-49). */
export function offersSender24h(form: Pick<RuleForm, 'direction' | 'condition'>): boolean {
  return form.direction === 'sent' && form.condition === 'content';
}

/** What the API keeps for the form: the 24-hour window and two approvers only where they apply. */
export function effectiveRuleOptions(form: Pick<RuleForm, 'direction' | 'condition' | 'action' | 'include_sender_24h' | 'approvals_required'>): {
  include_sender_24h: boolean;
  approvals_required: 1 | 2;
} {
  return {
    include_sender_24h: offersSender24h(form) && form.include_sender_24h,
    approvals_required: form.direction === 'sent' && form.action === 'require_approval' ? form.approvals_required : 1,
  };
}

export type RuleField = 'name' | 'detectors' | 'threshold' | 'reasons' | 'action';
export type RuleProblem = 'name' | 'detectors' | 'tooManyDetectors' | 'threshold' | 'reasons' | 'receivedAction';

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
  if (form.direction === 'received' && !RECEIVED_ACTIONS.includes(form.action)) problems.action = 'receivedAction';
  return problems;
}

/**
 * The `createDlpRule` body, or `null` while the form has problems. Only the condition's own fields are sent, and the
 * 24-hour window and two approvers only when chosen where they apply (their defaults are off and 1).
 */
export function ruleCreateBody(form: RuleForm, version: number): DlpRuleCreate | null {
  if (Object.keys(ruleProblems(form)).length > 0) return null;
  const body: DlpRuleCreate = {
    expected_version: version,
    name: form.name.trim(),
    enabled: form.enabled,
    direction: form.direction,
    condition: form.condition,
    recipient_scope: form.direction === 'received' ? 'any' : form.recipient_scope,
    action: form.action,
  };
  if (form.condition === 'content') {
    body.detectors = [...form.detectors];
    body.min_confidence = form.min_confidence;
    body.threshold = thresholdOf(form.threshold) as number;
  }
  if (form.condition === 'not_inspected') body.reasons = [...form.reasons];
  const options = effectiveRuleOptions(form);
  if (options.include_sender_24h) body.include_sender_24h = true;
  if (options.approvals_required === 2) body.approvals_required = 2;
  return body;
}

const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((item) => b.includes(item));

/** The fields of a rule the form changed, in the order the confirmation lists them. */
export type RuleChange =
  | 'name'
  | 'enabled'
  | 'detectors'
  | 'min_confidence'
  | 'threshold'
  | 'reasons'
  | 'include_sender_24h'
  | 'recipient_scope'
  | 'action'
  | 'approvals_required';

/**
 * The `updateDlpRule` body: only what changed, and the version loaded; `null` while the form has problems, and
 * `{ changes: [] }` when nothing changed. The condition and the direction are never changed: a rule keeps its kind.
 * A rule leaving "require approval" goes back to one approver, as the API needs.
 */
export function ruleUpdate(rule: DlpRule, form: RuleForm, version: number): { body: DlpRuleUpdate; changes: RuleChange[] } | null {
  const kept = { ...form, condition: rule.condition, direction: rule.direction };
  if (Object.keys(ruleProblems(kept)).length > 0) return null;
  const options = effectiveRuleOptions(kept);
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
  if (options.include_sender_24h !== rule.include_sender_24h) {
    body.include_sender_24h = options.include_sender_24h;
    changes.push('include_sender_24h');
  }
  if (rule.direction === 'sent' && form.recipient_scope !== rule.recipient_scope) {
    body.recipient_scope = form.recipient_scope;
    changes.push('recipient_scope');
  }
  if (form.action !== rule.action) {
    body.action = form.action;
    changes.push('action');
  }
  if (options.approvals_required !== rule.approvals_required) {
    body.approvals_required = options.approvals_required;
    changes.push('approvals_required');
  }
  return { body: changes.length > 0 ? { ...body, expected_version: version } : {}, changes };
}

/** The keyword lists a rule can name: `custom:<id>` of the tenant's own `keywords` detectors. */
export function keywordLists(detectors: readonly DlpDetector[]): DlpDetector[] {
  return detectors.filter((detector) => detector.kind === 'keywords');
}

/** The tenant's own patterns (`custom:<id>`, `kind: pattern`; FR-39). */
export function patterns(detectors: readonly DlpDetector[]): DlpDetector[] {
  return detectors.filter((detector) => detector.kind === 'pattern');
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
  const draft = keywordDefinition(form);
  return draft && { expected_version: version, ...draft };
}

function keywordDefinition(form: KeywordForm): DlpDetectorCreate | null {
  if (Object.keys(keywordProblems(form)).length > 0) return null;
  return { name: form.name.trim(), kind: 'keywords', keywords: parseTerms(form.terms).terms };
}

/** The name a draft is tested under when the form has none yet: the API needs one, and answers `draft` anyway. */
const DRAFT_NAME = 'draft';

/** The list as a `testDlpDetectors` draft (FR-56), or `null` while its terms have problems; the name may be blank. */
export function keywordDraft(form: KeywordForm): DlpDetectorCreate | null {
  return keywordDefinition({ ...form, name: form.name.trim() || DRAFT_NAME });
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

// ---- patterns (#221; FR-39, detectors 5) ----

export const PATTERN_MAX = 512;
export const MAX_CONTEXT_KEYWORDS = 50;
export const MIN_LENGTH_MAX = 1000;
/** The detector library stops counting a minimum length past this: a longer one acts as 512. */
export const MIN_LENGTH_EFFECTIVE_MAX = 512;
export const MAX_PATTERNS = 20;

/**
 * A pattern as the form holds it: an RE2 expression, context keywords one per line (a match near one is more
 * confident), whether it ignores case, and the shortest match that counts (blank for none). RE2 is checked on the
 * service, not here (JavaScript's syntax differs): a pattern that doesn't compile, matches the empty string or is too
 * complex comes back with a pointer to `#/pattern`.
 */
export interface PatternForm {
  name: string;
  pattern: string;
  context: string;
  case_insensitive: boolean;
  min_length: string;
}

export const emptyPatternForm: PatternForm = { name: '', pattern: '', context: '', case_insensitive: true, min_length: '' };

export function patternFormOf(detector: DlpDetector): PatternForm {
  return {
    name: detector.name,
    pattern: detector.pattern ?? '',
    context: (detector.context_keywords ?? []).join('\n'),
    case_insensitive: detector.case_insensitive ?? true,
    min_length: detector.min_length === undefined ? '' : String(detector.min_length),
  };
}

export type PatternField = 'name' | 'pattern' | 'context_keywords' | 'min_length';
export type PatternProblem = 'name' | 'noPattern' | 'patternTooLong' | 'tooManyContext' | 'contextTooLong' | 'minLength';
export const PATTERN_FIELDS: readonly PatternField[] = ['name', 'pattern', 'context_keywords', 'min_length'];

/** The minimum length as a whole number from 1 to 1,000; `undefined` when blank, `null` when it isn't one. */
export function minLengthOf(text: string): number | null | undefined {
  const value = text.trim();
  if (!value) return undefined;
  if (!/^\d+$/.test(value)) return null;
  const number = Number(value);
  return number >= 1 && number <= MIN_LENGTH_MAX ? number : null;
}

export function patternProblems(form: PatternForm): Partial<Record<PatternField, PatternProblem>> {
  const problems: Partial<Record<PatternField, PatternProblem>> = {};
  const name = form.name.trim();
  if (name.length === 0 || name.length > DETECTOR_NAME_MAX) problems.name = 'name';
  if (form.pattern.length === 0) problems.pattern = 'noPattern';
  else if ([...form.pattern].length > PATTERN_MAX) problems.pattern = 'patternTooLong';
  const { terms, tooLong } = parseTerms(form.context);
  if (tooLong.length > 0) problems.context_keywords = 'contextTooLong';
  else if (terms.length > MAX_CONTEXT_KEYWORDS) problems.context_keywords = 'tooManyContext';
  if (minLengthOf(form.min_length) === null) problems.min_length = 'minLength';
  return problems;
}

/** The `createDlpDetector` body for a pattern, or `null` while the form has problems. */
export function patternCreateBody(form: PatternForm, version: number): DlpDetectorCreate | null {
  const draft = patternDefinition(form);
  return draft && { expected_version: version, ...draft };
}

function patternDefinition(form: PatternForm): DlpDetectorCreate | null {
  if (Object.keys(patternProblems(form)).length > 0) return null;
  const minLength = minLengthOf(form.min_length);
  return {
    name: form.name.trim(),
    kind: 'pattern',
    pattern: form.pattern,
    context_keywords: parseTerms(form.context).terms,
    case_insensitive: form.case_insensitive,
    ...(minLength === undefined || minLength === null ? {} : { min_length: minLength }),
  };
}

/** The pattern as a `testDlpDetectors` draft (FR-56), or `null` while it has problems; the name may be blank. */
export function patternDraft(form: PatternForm): DlpDetectorCreate | null {
  return patternDefinition({ ...form, name: form.name.trim() || DRAFT_NAME });
}

export type PatternChange = 'name' | 'pattern' | 'context_keywords' | 'case_insensitive' | 'min_length';

/**
 * The `updateDlpDetector` body for a pattern: only what changed, and the version loaded. A minimum length can't be
 * taken away (the API has no "none"), so clearing it sends 1, which counts every match.
 */
export function patternUpdate(
  detector: DlpDetector,
  form: PatternForm,
  version: number,
): { body: DlpDetectorUpdate; changes: PatternChange[] } | null {
  if (Object.keys(patternProblems(form)).length > 0) return null;
  const body: DlpDetectorUpdate = {};
  const changes: PatternChange[] = [];
  const name = form.name.trim();
  if (name !== detector.name) {
    body.name = name;
    changes.push('name');
  }
  if (form.pattern !== (detector.pattern ?? '')) {
    body.pattern = form.pattern;
    changes.push('pattern');
  }
  const context = parseTerms(form.context).terms;
  if (context.join('\n') !== (detector.context_keywords ?? []).join('\n')) {
    body.context_keywords = context;
    changes.push('context_keywords');
  }
  if (form.case_insensitive !== (detector.case_insensitive ?? true)) {
    body.case_insensitive = form.case_insensitive;
    changes.push('case_insensitive');
  }
  const minLength = minLengthOf(form.min_length) ?? undefined;
  if (minLength !== detector.min_length) {
    if (minLength !== undefined) {
      body.min_length = minLength;
      changes.push('min_length');
    } else if (detector.min_length !== undefined && detector.min_length !== 1) {
      body.min_length = 1;
      changes.push('min_length');
    }
  }
  return { body: changes.length > 0 ? { ...body, expected_version: version } : {}, changes };
}

/**
 * `422 validation_failed` on a detector write or test: each issue on the field its pointer names (`#/pattern`,
 * `#/context_keywords/3`, a draft's `#/draft/pattern`), the rest apart.
 */
export function detectorFieldErrors(
  fields: Record<string, string>,
): { byField: Partial<Record<PatternField | 'keywords', string>>; other: string[] } {
  const byField: Partial<Record<PatternField | 'keywords', string>> = {};
  const other: string[] = [];
  for (const [pointer, detail] of Object.entries(fields)) {
    const parts = pointer.split('/');
    const field = parts[0] === 'draft' ? parts[1] : parts[0];
    if (field && ([...PATTERN_FIELDS, 'keywords'] as string[]).includes(field)) byField[field as PatternField | 'keywords'] ??= detail;
    else other.push(detail);
  }
  return { byField, other };
}

// ---- detector tests (#221; FR-56) ----

export const TEST_TEXT_MAX = 16_384;

/**
 * What `testDlpDetectors` gets: the existing detector alone when the form is unchanged, else the draft. `null` when
 * there is nothing to test yet (a new form with problems) or the text is empty or too long.
 */
export function detectorTestBody(
  text: string,
  existingId: string | null,
  changed: boolean,
  draft: DlpDetectorCreate | null,
): Schema<'DlpDetectorTest'> | null {
  if (text.length === 0 || [...text].length > TEST_TEXT_MAX) return null;
  if (existingId && !changed) return { text, detectors: [existingId] };
  return draft ? { text, draft } : null;
}
