import i18n from 'i18next';
import { describe, expect, it } from 'vitest';
import '@/lib/i18n';
import type { DlpDetector, DlpPolicy, DlpRule } from '@/api';
import {
  addDomains,
  approvalTimeoutOptions,
  detectorFieldErrors,
  detectorTestBody,
  emptyPatternForm,
  emptyRuleForm,
  isApprovalTimeout,
  keywordCreateBody,
  keywordDraft,
  keywordFormOf,
  keywordProblems,
  keywordUpdate,
  MAX_TERMS,
  MAX_TRUSTED_DOMAINS,
  normalizeDomain,
  parseTerms,
  patternCreateBody,
  patternDraft,
  patternFormOf,
  patternProblems,
  patterns,
  patternUpdate,
  ruleCreateBody,
  ruleFormOf,
  ruleProblems,
  ruleUpdate,
  settingsFormOf,
  settingsUpdate,
  TEST_TEXT_MAX,
  withDirection,
} from './dlpForms';
import { conditionText, ruleOptionNotes } from './ruleText';

const policy: DlpPolicy = {
  mode: 'enforce',
  version: 7,
  trusted_domains: ['partner.example'],
  approval_timeout: 'PT72H',
  active_approvers: 2,
  updated_at: '2026-11-01T00:00:00Z',
  updated_by: null,
};

const rule: DlpRule = {
  id: '0190c0de-0000-7000-8000-0000000000d1',
  revision: 3,
  name: 'My Numbers',
  enabled: true,
  direction: 'sent',
  condition: 'content',
  detectors: ['jp_my_number'],
  min_confidence: 'high',
  threshold: 1,
  reasons: [],
  include_sender_24h: false,
  recipient_scope: 'any',
  action: 'warn',
  approvals_required: 1,
  created_by: '0190c0de-0000-7000-8000-000000000001',
  created_at: '2026-11-01T00:00:00Z',
};

const list: DlpDetector = {
  id: 'custom:0190c0de-0000-7000-8000-0000000000c1',
  kind: 'keywords',
  name: 'Project names',
  enabled: true,
  revision: 2,
  keywords: ['Bluebird', '青い鳥'],
};

describe('trusted domains (#218, FR-45)', () => {
  it('keeps domains lowercase, without a trailing dot, and refuses anything else', () => {
    expect(normalizeDomain(' Partner.Example. ')).toBe('partner.example');
    expect(normalizeDomain('例え.jp')).toBe('例え.jp');
    for (const bad of ['', 'localhost', 'https://partner.example', 'a@partner.example', '-bad.example', 'bad-.example', 'a..b']) {
      expect(normalizeDomain(bad), bad).toBeNull();
    }
  });

  it('adds several at once, once each, and says which were refused', () => {
    expect(addDomains(['partner.example'], 'b.example, Partner.example\nc.example nope')).toEqual({
      domains: ['partner.example', 'b.example', 'c.example'],
      invalid: ['nope'],
      overLimit: [],
    });
  });

  it('stops at 500', () => {
    const full = Array.from({ length: MAX_TRUSTED_DOMAINS }, (_, index) => `d${index}.example`);
    const added = addDomains(full, 'one-more.example');
    expect(added.domains).toHaveLength(MAX_TRUSTED_DOMAINS);
    expect(added.overLimit).toEqual(['one-more.example']);
  });
});

describe('the settings body (#218)', () => {
  it('sends nothing when nothing changed, the same timeout in another spelling included', () => {
    expect(settingsUpdate(policy, settingsFormOf(policy))).toBeNull();
    expect(settingsFormOf(policy).approval_timeout).toBe('P3D');
  });

  it('sends only what changed, with the version loaded, and the mode only when it changed (#221)', () => {
    const form = { ...settingsFormOf(policy), trusted_domains: ['partner.example', 'new.example'] };
    expect(settingsUpdate(policy, form)).toEqual({ trusted_domains: ['partner.example', 'new.example'], expected_version: 7 });
    expect(settingsUpdate(policy, { ...settingsFormOf(policy), approval_timeout: 'P1D' })).toEqual({
      approval_timeout: 'P1D',
      expected_version: 7,
    });
    expect(settingsFormOf(policy).mode).toBe('enforce');
    expect(settingsUpdate(policy, { ...settingsFormOf(policy), mode: 'monitor' })).toEqual({ mode: 'monitor', expected_version: 7 });
    expect(settingsUpdate({ ...policy, mode: 'monitor' }, { ...settingsFormOf(policy), mode: 'monitor' })).toBeNull();
  });

  it('keeps the timeout between 1 hour and 7 days', () => {
    expect(isApprovalTimeout('PT1H')).toBe(true);
    expect(isApprovalTimeout('P7D')).toBe(true);
    expect(isApprovalTimeout('PT59M')).toBe(false);
    expect(isApprovalTimeout('P8D')).toBe(false);
    expect(settingsUpdate(policy, { ...settingsFormOf(policy), approval_timeout: 'P8D' })).toBeNull();
    expect(approvalTimeoutOptions('PT5H')).toContain('PT5H');
    expect(approvalTimeoutOptions('PT72H')).not.toContain('PT72H');
  });
});

describe('the rule form (#218, FR-40, FR-41)', () => {
  it('creates a content rule for sent files with only its own fields', () => {
    const form = { ...emptyRuleForm, name: ' Bluebird ', detectors: [list.id], threshold: '3', action: 'block' as const };
    expect(ruleCreateBody(form, 7)).toEqual({
      expected_version: 7,
      name: 'Bluebird',
      enabled: true,
      direction: 'sent',
      condition: 'content',
      recipient_scope: 'any',
      action: 'block',
      detectors: [list.id],
      min_confidence: 'medium',
      threshold: 3,
    });
  });

  it('creates a not-inspected rule with its reasons, and leaves out the options at their defaults', () => {
    const body = ruleCreateBody({ ...emptyRuleForm, name: 'Encrypted', condition: 'not_inspected', reasons: ['encrypted'] }, 7);
    expect(body).toMatchObject({ condition: 'not_inspected', reasons: ['encrypted'], direction: 'sent' });
    expect(body).not.toHaveProperty('detectors');
    expect(body).not.toHaveProperty('include_sender_24h');
    expect(body).not.toHaveProperty('approvals_required');
  });

  it('names what is missing', () => {
    expect(ruleProblems(emptyRuleForm)).toEqual({ name: 'name', detectors: 'detectors' });
    expect(ruleProblems({ ...emptyRuleForm, name: 'x', detectors: ['iban'], threshold: '0' })).toEqual({ threshold: 'threshold' });
    expect(ruleProblems({ ...emptyRuleForm, name: 'x', detectors: ['iban'], threshold: '100001' })).toEqual({ threshold: 'threshold' });
    expect(ruleProblems({ ...emptyRuleForm, name: 'x', condition: 'not_inspected' })).toEqual({ reasons: 'reasons' });
    expect(ruleCreateBody(emptyRuleForm, 7)).toBeNull();
  });

  it('changes only what the admin changed, and nothing when nothing changed', () => {
    expect(ruleUpdate(rule, ruleFormOf(rule), 7)).toEqual({ body: {}, changes: [] });
    const form = { ...ruleFormOf(rule), action: 'block' as const, detectors: ['jp_my_number'], threshold: '5' };
    expect(ruleUpdate(rule, form, 7)).toEqual({
      body: { action: 'block', threshold: 5, expected_version: 7 },
      changes: ['threshold', 'action'],
    });
  });

  it('lets a new-domain rule from the default policy change its action', () => {
    const newDomain: DlpRule = { ...rule, condition: 'new_domain', detectors: [], name: 'New recipient domain' };
    expect(ruleUpdate(newDomain, { ...ruleFormOf(newDomain), action: 'require_approval' }, 7)).toEqual({
      body: { action: 'require_approval', expected_version: 7 },
      changes: ['action'],
    });
  });

  it('says a condition in words, with the detectors\' names', () => {
    const t = i18n.getFixedT('en');
    expect(conditionText({ ...rule, detectors: ['jp_my_number', list.id], threshold: 2 }, [list], t)).toBe(
      'My Number (Individual Number), Project names: 2 or more at high confidence',
    );
    expect(conditionText({ ...rule, condition: 'not_inspected', reasons: ['encrypted', 'too_large'] }, [], t)).toBe(
      'Not fully inspected because encrypted, over 2 GB',
    );
  });
});

describe('keyword lists (#218, FR-38)', () => {
  it('takes one term per line, trimmed, once each', () => {
    expect(parseTerms(' Bluebird \n\n青い鳥\r\nBluebird\n')).toEqual({ terms: ['Bluebird', '青い鳥'], tooLong: [], duplicates: 1 });
  });

  it('needs 1 to 1,000 terms of at most 100 characters', () => {
    expect(keywordProblems({ name: 'x', terms: '' })).toEqual({ terms: 'noTerms' });
    expect(keywordProblems({ name: '', terms: 'a' })).toEqual({ name: 'name' });
    expect(keywordProblems({ name: 'x', terms: 'あ'.repeat(101) })).toEqual({ terms: 'termTooLong' });
    expect(keywordProblems({ name: 'x', terms: 'あ'.repeat(100) })).toEqual({});
    const many = Array.from({ length: MAX_TERMS + 1 }, (_, index) => `term${index}`).join('\n');
    expect(keywordProblems({ name: 'x', terms: many })).toEqual({ terms: 'tooManyTerms' });
  });

  it('creates a keyword list with the version loaded', () => {
    expect(keywordCreateBody({ name: ' Codes ', terms: 'A\nB' }, 7)).toEqual({
      expected_version: 7,
      name: 'Codes',
      kind: 'keywords',
      keywords: ['A', 'B'],
    });
  });

  it('sends the terms only when they changed, and counts what was added and removed', () => {
    expect(keywordUpdate(list, keywordFormOf(list), 7)).toEqual({ body: {}, changes: [], added: 0, removed: 0 });
    expect(keywordUpdate(list, { name: list.name, terms: 'Bluebird\nRedbird' }, 7)).toEqual({
      body: { keywords: ['Bluebird', 'Redbird'], expected_version: 7 },
      changes: ['terms'],
      added: 1,
      removed: 1,
    });
  });
});

describe('rules for received files, the 24-hour window and two approvers (#221; FR-44, FR-49, FR-51)', () => {
  const content = { ...emptyRuleForm, name: 'Uploads with My Numbers', detectors: ['jp_my_number'] };

  it('creates a rule for received files that records or blocks, with no recipients and no 24-hour window', () => {
    const form = withDirection({ ...content, recipient_scope: 'untrusted', include_sender_24h: true, action: 'warn' }, 'received');
    expect(form).toMatchObject({ direction: 'received', recipient_scope: 'any', include_sender_24h: false, action: 'block' });
    expect(ruleCreateBody(form, 7)).toEqual({
      expected_version: 7,
      name: 'Uploads with My Numbers',
      enabled: true,
      direction: 'received',
      condition: 'content',
      recipient_scope: 'any',
      action: 'block',
      detectors: ['jp_my_number'],
      min_confidence: 'medium',
      threshold: 1,
    });
    expect(withDirection({ ...content, action: 'allow_and_record' }, 'received').action).toBe('allow_and_record');
  });

  it('refuses an action a rule for received files can\'t take', () => {
    expect(ruleProblems({ ...content, direction: 'received', action: 'require_approval' })).toEqual({ action: 'receivedAction' });
    expect(ruleCreateBody({ ...content, direction: 'received', action: 'warn' }, 7)).toBeNull();
  });

  it('sends the 24-hour window only on a content rule for sent files', () => {
    expect(ruleCreateBody({ ...content, include_sender_24h: true }, 7)).toMatchObject({ include_sender_24h: true });
    const notInspected = { ...emptyRuleForm, name: 'x', condition: 'not_inspected' as const, reasons: ['encrypted' as const], include_sender_24h: true };
    expect(ruleCreateBody(notInspected, 7)).not.toHaveProperty('include_sender_24h');
  });

  it('sends two approvers only with "require approval"', () => {
    expect(ruleCreateBody({ ...content, action: 'require_approval', approvals_required: 2 }, 7)).toMatchObject({
      action: 'require_approval',
      approvals_required: 2,
    });
    expect(ruleCreateBody({ ...content, action: 'warn', approvals_required: 2 }, 7)).not.toHaveProperty('approvals_required');
  });

  it('updates the options, and goes back to one approver when the rule stops requiring approval', () => {
    const twoApprovers: DlpRule = { ...rule, action: 'require_approval', approvals_required: 2 };
    expect(ruleUpdate(twoApprovers, ruleFormOf(twoApprovers), 7)).toEqual({ body: {}, changes: [] });
    expect(ruleUpdate(twoApprovers, { ...ruleFormOf(twoApprovers), action: 'block' }, 7)).toEqual({
      body: { action: 'block', approvals_required: 1, expected_version: 7 },
      changes: ['action', 'approvals_required'],
    });
    expect(ruleUpdate(rule, { ...ruleFormOf(rule), include_sender_24h: true }, 7)).toEqual({
      body: { include_sender_24h: true, expected_version: 7 },
      changes: ['include_sender_24h'],
    });
  });

  it('never changes a rule\'s direction, and gives a received rule no recipients', () => {
    const received: DlpRule = { ...rule, direction: 'received', action: 'block' };
    const update = ruleUpdate(received, { ...ruleFormOf(received), direction: 'sent', recipient_scope: 'untrusted' }, 7);
    expect(update).toEqual({ body: {}, changes: [] });
    expect(ruleUpdate(received, { ...ruleFormOf(received), action: 'warn' }, 7)).toBeNull();
  });

  it('notes the options in the rules list', () => {
    const t = i18n.getFixedT('en');
    expect(ruleOptionNotes({ ...rule, include_sender_24h: true, action: 'require_approval', approvals_required: 2 }, t)).toEqual([
      'Includes the sender\'s last 24 hours',
      'Two approvers',
    ]);
    expect(ruleOptionNotes(rule, t)).toEqual([]);
  });
});

const pattern: DlpDetector = {
  id: 'custom:0190c0de-0000-7000-8000-0000000000c9',
  kind: 'pattern',
  name: 'Invoice numbers',
  enabled: true,
  revision: 1,
  pattern: 'INV-[0-9]{6}',
  context_keywords: ['invoice', '請求書'],
  case_insensitive: true,
  min_length: 10,
  budget_exceeded_files: 3,
  budget_exceeded_last_at: '2026-11-07T00:00:00Z',
};

describe('patterns (#221; FR-39, detectors 5)', () => {
  it('finds the patterns among the detectors', () => {
    expect(patterns([list, pattern]).map((detector) => detector.id)).toEqual([pattern.id]);
  });

  it('needs a name and a pattern of at most 512 characters, at most 50 context keywords and a whole minimum length', () => {
    expect(patternProblems(emptyPatternForm)).toEqual({ name: 'name', pattern: 'noPattern' });
    const form = { ...emptyPatternForm, name: 'x', pattern: 'a' };
    expect(patternProblems(form)).toEqual({});
    expect(patternProblems({ ...form, pattern: 'a'.repeat(513) })).toEqual({ pattern: 'patternTooLong' });
    expect(patternProblems({ ...form, context: Array.from({ length: 51 }, (_, i) => `w${i}`).join('\n') })).toEqual({
      context_keywords: 'tooManyContext',
    });
    expect(patternProblems({ ...form, context: 'x'.repeat(101) })).toEqual({ context_keywords: 'contextTooLong' });
    for (const bad of ['0', '1001', '1.5', 'ten']) expect(patternProblems({ ...form, min_length: bad }), bad).toEqual({ min_length: 'minLength' });
    expect(patternProblems({ ...form, min_length: '1000' })).toEqual({});
  });

  it('creates a pattern with its context keywords, case and minimum length', () => {
    expect(
      patternCreateBody({ name: ' Invoices ', pattern: 'INV-[0-9]{6}', context: 'invoice\n\n請求書\ninvoice', case_insensitive: false, min_length: '10' }, 7),
    ).toEqual({
      expected_version: 7,
      name: 'Invoices',
      kind: 'pattern',
      pattern: 'INV-[0-9]{6}',
      context_keywords: ['invoice', '請求書'],
      case_insensitive: false,
      min_length: 10,
    });
    expect(patternCreateBody({ ...emptyPatternForm, name: 'x', pattern: 'a' }, 7)).not.toHaveProperty('min_length');
  });

  it('sends only what changed, and a cleared minimum length as 1', () => {
    expect(patternUpdate(pattern, patternFormOf(pattern), 7)).toEqual({ body: {}, changes: [] });
    expect(patternUpdate(pattern, { ...patternFormOf(pattern), pattern: 'INV-[0-9]{8}', case_insensitive: false }, 7)).toEqual({
      body: { pattern: 'INV-[0-9]{8}', case_insensitive: false, expected_version: 7 },
      changes: ['pattern', 'case_insensitive'],
    });
    expect(patternUpdate(pattern, { ...patternFormOf(pattern), min_length: '' }, 7)).toEqual({
      body: { min_length: 1, expected_version: 7 },
      changes: ['min_length'],
    });
    expect(patternUpdate(pattern, { ...patternFormOf(pattern), context: 'invoice' }, 7)?.body).toEqual({
      context_keywords: ['invoice'],
      expected_version: 7,
    });
  });

  it('puts a refusal on the field its pointer names, a draft\'s too', () => {
    expect(detectorFieldErrors({ pattern: 'Matches the empty string.', 'context_keywords/3': 'Too long.', colour: 'Unknown.' })).toEqual({
      byField: { pattern: 'Matches the empty string.', context_keywords: 'Too long.' },
      other: ['Unknown.'],
    });
    expect(detectorFieldErrors({ 'draft/pattern': 'Too complex.' }).byField).toEqual({ pattern: 'Too complex.' });
  });
});

describe('detector tests (#221; FR-56)', () => {
  it('tests a draft without a name, never with the version', () => {
    expect(patternDraft({ ...emptyPatternForm, pattern: 'INV-[0-9]{6}' })).toEqual({
      name: 'draft',
      kind: 'pattern',
      pattern: 'INV-[0-9]{6}',
      context_keywords: [],
      case_insensitive: true,
    });
    expect(keywordDraft({ name: 'Codes', terms: 'A\nB' })).toEqual({ name: 'Codes', kind: 'keywords', keywords: ['A', 'B'] });
    expect(keywordDraft({ name: '', terms: '' })).toBeNull();
  });

  it('tests the saved detector while unchanged, else the draft, and nothing without text or past 16,384 characters', () => {
    const draft = keywordDraft({ name: 'Codes', terms: 'A' });
    expect(detectorTestBody('text', list.id, false, draft)).toEqual({ text: 'text', detectors: [list.id] });
    expect(detectorTestBody('text', list.id, true, draft)).toEqual({ text: 'text', draft });
    expect(detectorTestBody('text', null, true, null)).toBeNull();
    expect(detectorTestBody('', list.id, false, draft)).toBeNull();
    expect(detectorTestBody('あ'.repeat(TEST_TEXT_MAX), null, true, draft)).not.toBeNull();
    expect(detectorTestBody('あ'.repeat(TEST_TEXT_MAX + 1), null, true, draft)).toBeNull();
  });
});
