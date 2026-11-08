import { describe, expect, it } from 'vitest';
import type { FileState, TransferState } from '@/api';
import { APPROVAL_POLL_INTERVAL_MS, POLL_INTERVAL_MS, pollInterval, shouldPoll, useActiveUploads } from './polling';

const transfer = (state: TransferState, files: FileState[]) => ({
  state,
  files: files.map((fileState, index) => ({ id: `f${index}`, state: fileState })) as never,
});

describe('shouldPoll: the detail page polls only while something moves (#196)', () => {
  it('polls while the transfer is submitted, or a file completes or is scanned', () => {
    expect(shouldPoll(transfer('submitted', ['clean']))).toBe(true);
    expect(shouldPoll(transfer('draft', ['clean', 'completing']))).toBe(true);
    expect(shouldPoll(transfer('submitted', ['scanning']))).toBe(true);
    expect(shouldPoll(transfer('draft', ['scanning']))).toBe(true);
  });

  it('polls for an uploading file only while this tab uploads it (#196 review)', () => {
    // A stalled draft: nobody uploads here, so nothing moves until the member picks the file again.
    expect(shouldPoll(transfer('draft', ['uploading']))).toBe(false);
    expect(shouldPoll(transfer('draft', ['uploading', 'uploading']), new Set(['f1']))).toBe(true);
    expect(shouldPoll(transfer('draft', ['uploading']), new Set(['another-file']))).toBe(false);
  });

  it('stops once every file has its result and the transfer has moved on', () => {
    for (const state of ['sent', 'held', 'revoked', 'expired', 'cancelled', 'draft'] as TransferState[]) {
      expect(shouldPoll(transfer(state, ['clean', 'infected', 'unscannable', 'scan_failed', 'rejected', 'deleted']))).toBe(false);
    }
    expect(shouldPoll(transfer('draft', []))).toBe(false);
    expect(shouldPoll(undefined)).toBe(false);
  });

  it('tracks the uploads this tab runs', () => {
    useActiveUploads.getState().start('f0');
    expect(shouldPoll(transfer('draft', ['uploading']), useActiveUploads.getState().ids)).toBe(true);
    useActiveUploads.getState().stop('f0');
    expect(shouldPoll(transfer('draft', ['uploading']), useActiveUploads.getState().ids)).toBe(false);
  });
});

describe('pollInterval: DLP states (#219, #220)', () => {
  it('asks every 15 seconds while an approver decides', () => {
    expect(pollInterval(transfer('pending_approval', ['clean']))).toBe(APPROVAL_POLL_INTERVAL_MS);
  });

  it('waits for the sender while a warning or a block is shown', () => {
    expect(pollInterval(transfer('awaiting_confirmation', ['clean']))).toBe(false);
    expect(pollInterval(transfer('held', ['clean']))).toBe(false);
  });

  it('keeps the quick poll while the service moves the transfer', () => {
    expect(pollInterval(transfer('submitted', ['clean']))).toBe(POLL_INTERVAL_MS);
    expect(pollInterval(transfer('pending_approval', ['scanning']))).toBe(POLL_INTERVAL_MS);
    expect(pollInterval(undefined)).toBe(false);
  });
});
