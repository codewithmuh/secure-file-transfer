import { describe, expect, it } from 'vitest';
import type { DlpDecision, TransferDlp } from '@/api';
import { dlpSignature } from '@/hooks/dlp';
import { dlpStage, filesToRemove, findingTotal, flaggedRecipients, showsDlp, textProblem } from './dlpView';

const decision = (outcome: DlpDecision['outcome'], rules: DlpDecision['matched_rules'] = []): DlpDecision => ({
  id: 'd1',
  transfer_id: 't1',
  file_id: null,
  policy_version: 3,
  mode: 'enforce',
  outcome,
  enforced: true,
  untrusted_recipients: 1,
  new_domains: 1,
  matched_rules: rules,
  decided_at: '2026-11-08T00:00:00Z',
});

const matched = (action: DlpDecision['matched_rules'][number]['action'], condition: DlpDecision['matched_rules'][number]['condition']) => ({
  rule_id: `r-${action}-${condition}`,
  revision: 1,
  name: `${action} ${condition}`,
  condition,
  action,
  matched_count: 2,
  threshold: condition === 'content' ? 1 : null,
});

const dlpFile = (id: string, findings: number, state: TransferDlp['files'][number]['inspection']['state'] = 'inspected') => ({
  file_id: id,
  display_name: `${id}.txt`,
  inspection: { state, reasons: [], dlp_blocked: false, detectors: [] },
  findings: Array.from({ length: findings }, (_, index) => ({
    detector: `d${index}`,
    detector_name: `D${index}`,
    count_low: 0,
    count_medium: 1,
    count_high: 0,
    details_visible: false,
  })),
});

describe('the DLP stage of a transfer (#219, #220)', () => {
  it('is shown for awaiting confirmation, pending approval, and a DLP hold only', () => {
    expect(showsDlp({ state: 'awaiting_confirmation', hold_reason: null })).toBe(true);
    expect(showsDlp({ state: 'pending_approval', hold_reason: null })).toBe(true);
    expect(showsDlp({ state: 'held', hold_reason: 'dlp_blocked' })).toBe(true);
    expect(showsDlp({ state: 'held', hold_reason: 'approval_rejected' })).toBe(true);
    expect(showsDlp({ state: 'held', hold_reason: 'file_blocked' })).toBe(false);
    expect(showsDlp({ state: 'sent', hold_reason: null })).toBe(false);
  });

  it('asks to confirm a warning and to request approval when a rule requires it', () => {
    const waiting = { state: 'awaiting_confirmation' as const, hold_reason: null };
    expect(dlpStage(waiting, { decision: null })).toBe('checking');
    expect(dlpStage(waiting, { decision: decision('warn') })).toBe('confirm');
    expect(dlpStage(waiting, { decision: decision('require_approval') })).toBe('approval');
    expect(dlpStage({ state: 'pending_approval', hold_reason: null }, { decision: decision('require_approval') })).toBe('pending');
    expect(dlpStage({ state: 'held', hold_reason: 'dlp_blocked' }, undefined)).toBe('blocked');
    expect(dlpStage({ state: 'held', hold_reason: 'approval_rejected' }, undefined)).toBe('rejected');
    expect(dlpStage({ state: 'sent', hold_reason: null }, { decision: decision('warn') })).toBeNull();
  });

  it('fetches the view again when the state, the outcome or the request changes', () => {
    const base = { state: 'awaiting_confirmation' as const, hold_reason: null, dlp: null };
    const warned = { ...base, dlp: { outcome: 'warn' as const, mode: 'enforce' as const, enforced: true, approval_request_id: null } };
    const requested = { ...warned, state: 'pending_approval' as const, dlp: { ...warned.dlp, approval_request_id: 'a1' } };
    expect(new Set([dlpSignature(base), dlpSignature(warned), dlpSignature(requested)]).size).toBe(3);
  });
});

describe('what the panel shows (#219)', () => {
  it('flags recipients outside the trusted domains or new to the tenant', () => {
    const check = (email: string, trusted: boolean, newDomain: boolean) => ({ recipient_id: email, email, trusted, new_domain: newDomain });
    const flagged = flaggedRecipients([check('a@ok.example', true, false), check('b@new.example', true, true), check('c@x.example', false, false)]);
    expect(flagged.map((recipient) => recipient.email)).toEqual(['b@new.example', 'c@x.example']);
  });

  it('adds up a finding at every confidence', () => {
    expect(findingTotal({ count_low: 1, count_medium: 2, count_high: 3 })).toBe(6);
  });

  it('marks the files a blocking rule could have counted', () => {
    const files = [dlpFile('a', 1), dlpFile('b', 0), dlpFile('c', 0, 'not_inspected')];
    expect(filesToRemove({ decision: decision('block', [matched('block', 'content')]), files })).toEqual(['a']);
    expect(filesToRemove({ decision: decision('block', [matched('block', 'not_inspected')]), files })).toEqual(['c']);
    // A warning alone marks nothing to remove.
    expect(filesToRemove({ decision: decision('warn', [matched('warn', 'content')]), files })).toEqual([]);
  });

  it('needs a justification for approval, at most 1,000 characters', () => {
    expect(textProblem('', false)).toBeNull();
    expect(textProblem('   ', true)).toBe('required');
    expect(textProblem('Client asked for it', true)).toBeNull();
    expect(textProblem('あ'.repeat(1001), false)).toBe('tooLong');
    expect(textProblem('あ'.repeat(1000), true)).toBeNull();
  });
});
