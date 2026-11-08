import i18n from 'i18next';
import { describe, expect, it } from 'vitest';
import '@/lib/i18n';
import type { DlpDetector, DlpPolicy, DlpRule } from '@/api';
import {
  addDomains,
  approvalTimeoutOptions,
  emptyRuleForm,
  isApprovalTimeout,
  keywordCreateBody,
  keywordFormOf,
  keywordProblems,
  keywordUpdate,
  MAX_TERMS,
  MAX_TRUSTED_DOMAINS,
  normalizeDomain,
  parseTerms,
  ruleCreateBody,
  ruleFormOf,
  ruleProblems,
  ruleUpdate,
  settingsFormOf,
  settingsUpdate,
} from './dlpForms';
import { conditionText } from './ruleText';

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

  it('sends only what changed, with the version loaded, and never the mode', () => {
    const form = { ...settingsFormOf(policy), trusted_domains: ['partner.example', 'new.example'] };
    expect(settingsUpdate(policy, form)).toEqual({ trusted_domains: ['partner.example', 'new.example'], expected_version: 7 });
    expect(settingsUpdate(policy, { ...settingsFormOf(policy), approval_timeout: 'P1D' })).toEqual({
      approval_timeout: 'P1D',
      expected_version: 7,
    });
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

  it('creates a not-inspected rule with its reasons, and never sends what the API refuses until #221', () => {
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
