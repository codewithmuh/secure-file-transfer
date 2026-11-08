import { describe, expect, it, vi } from 'vitest';
import { renderToString } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AxiosError, AxiosHeaders, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import i18n from 'i18next';
import '@/lib/i18n';
import { resources } from '@/lib/i18n';
import { ApproveDialog, RejectDialog } from '@/features/approvals/DecisionDialogs';
import { ConfirmSend } from '@/features/sender/TransferDlpPanel';
import { ConfirmChange } from './ConfirmChange';

/**
 * The DLP dialogs (#218 to #220), rendered to a string as the first render after opening (Vitest runs without a
 * DOM): what each names and asks for. axe checks them in a browser (e2e/pages.a11y.ts).
 */

const en = resources.en.translation;
const html = (text: string) => text.replace(/'/g, '&#x27;').replace(/"/g, '&quot;');

function apiError(status: number, code: string): AxiosError {
  const config = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig;
  const data = { type: `https://secure-file-transfer.example/problems/${code}`, title: code, status, code };
  const response: AxiosResponse = { status, statusText: '', data, headers: new AxiosHeaders(), config };
  return new AxiosError(`status ${status}`, 'ERR_BAD_REQUEST', config, null, response);
}

const render = (node: React.ReactNode) =>
  renderToString(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );

describe('ConfirmChange (#218)', () => {
  const props = {
    open: true,
    title: en.dlpAdmin.confirmSettings,
    lines: ['Trust partner.example', 'Stop trusting old.example'],
    action: en.common.save,
    busy: false,
    onConfirm: vi.fn(),
    onClose: vi.fn(),
    onReload: vi.fn(),
  };

  it('names every change before anything is sent', () => {
    const out = render(<ConfirmChange {...props} error={null} />);
    expect(out).toContain('role="dialog"');
    expect(out).toContain('Trust partner.example');
    expect(out).toContain('Stop trusting old.example');
    expect(out).toContain(html(en.dlpAdmin.confirmNote));
  });

  it('offers to load the policy again after 409 dlp_policy_conflict, and won\'t send the stale change', () => {
    const out = render(<ConfirmChange {...props} error={apiError(409, 'dlp_policy_conflict')} />);
    expect(out).toContain(html(en.problems.dlp_policy_conflict));
    expect(out).toContain(en.dlpAdmin.reload);
    expect(out).toMatch(/<button[^>]*disabled=""[^>]*>Save<\/button>/);
  });

  it('explains a step-up instead of the bare problem', () => {
    const out = render(<ConfirmChange {...props} error={apiError(401, 'reauthentication_required')} />);
    expect(out).toContain(en.admin.signInAgain);
  });
});

describe('ConfirmSend (#219, #220)', () => {
  const rules = [
    { rule_id: 'r1', revision: 1, name: 'My Numbers', condition: 'content' as const, action: 'warn' as const, matched_count: 2, threshold: 1 },
  ];

  it('sends a warned transfer with an optional justification, naming the rules', () => {
    const out = render(<ConfirmSend transferId="t1" decisionId="d1" approval={false} rules={rules} onChanged={vi.fn()} initiallyOpen />);
    expect(out).toContain(en.dlp.confirm.warning.title);
    expect(out).toContain('My Numbers');
    expect(out).toContain(en.dlp.justificationOptional);
    expect(out).not.toContain('required=""');
  });

  it('asks for approval with a required justification', () => {
    const out = render(<ConfirmSend transferId="t1" decisionId="d1" approval rules={rules} onChanged={vi.fn()} initiallyOpen />);
    expect(out).toContain(en.dlp.confirm.approval.title);
    expect(out).toContain(en.dlp.justificationRequired);
    expect(out).toContain('required=""');
    expect(out).toContain(html(en.dlp.confirm.approval.note));
  });

  it('is in Japanese for a Japanese page', async () => {
    await i18n.changeLanguage('ja');
    try {
      const out = render(<ConfirmSend transferId="t1" decisionId="d1" approval rules={rules} onChanged={vi.fn()} initiallyOpen />);
      expect(out).toContain(resources.ja.translation.dlp.confirm.approval.title);
    } finally {
      await i18n.changeLanguage('en');
    }
  });
});

describe('the approve and reject dialogs (#220)', () => {
  it('says approving needs a recent sign-in, and a comment is optional', () => {
    const out = render(<ApproveDialog open onDecide={vi.fn()} onClose={vi.fn()} />);
    expect(out).toContain(en.approvals.approve.title);
    expect(out).toContain(en.approvals.approve.stepUp);
    expect(out).toContain(en.approvals.commentOptional);
  });

  it('needs a comment to reject, and asks no step-up', () => {
    const out = render(<RejectDialog open onDecide={vi.fn()} onClose={vi.fn()} />);
    expect(out).toContain(en.approvals.reject.title);
    expect(out).toContain(en.approvals.commentRequired);
    expect(out).toContain('required=""');
    expect(out).not.toContain(en.approvals.approve.stepUp);
  });
});
