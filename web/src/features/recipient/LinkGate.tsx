import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertCircle, CheckCircle2, Clock, Lock, Mail, Shield } from 'lucide-react';
import { Button, Card, Spinner } from '@/components/ui';
import { useAuthStore, type LinkMode } from '@/stores/authStore';
import {
  applyLinkLocale,
  goneOf,
  linkProblemText,
  resolveLink,
  resumeLinkSession,
  type LinkGone,
  type VerifiedSession,
} from './linkApi';
import { StepHeading } from './StepHeading';
import { VerificationPage } from './VerificationPage';

/** What the verified page can tell the gate: the link turned out gone, or the person is done. */
export interface GateActions {
  gone: (gone: LinkGone) => void;
  done: () => void;
}

type Phase =
  | { name: 'resolving' }
  | { name: 'missing' }
  | { name: 'gone'; gone: LinkGone }
  | { name: 'error'; error: unknown }
  | { name: 'verify' }
  | { name: 'verified'; session: VerifiedSession }
  | { name: 'done' };

/**
 * The steps of a public link page before its content (#198), for `/t` now and `/u` in M5:
 *
 * 1. `resolveLink` with the token `captureLinkToken` kept from the fragment. `404 link_not_found`, `410 link_revoked`,
 *    `410 link_expired` and a `locked` link each get their own page. `verified` with a `link_session_id` resumes that
 *    session with `getLinkSession`, with no new code: the link opened again in this browser (a second tab, or the same
 *    tab after a reload). A reload alone doesn't: the token is in memory only, so the reloaded page has none and asks
 *    the person to open the link from their email again.
 * 2. The page's language follows the link's `locale` (FR-33).
 * 3. Verification (`VerificationPage`), then `children` with the verified session.
 *
 * A `401` on any `/session` call ends the session in the store (the API client's interceptor), and the gate goes back
 * to the code step with the "session ended" note. Focus moves to each step's heading (`StepHeading`).
 */
export function LinkGate({
  mode,
  children,
}: {
  mode: LinkMode;
  children: (session: VerifiedSession, actions: GateActions) => ReactNode;
}) {
  const { t } = useTranslation();
  // The kept token as an object: opening the link again in this tab keeps a new one, which resolves again.
  const kept = useAuthStore((s) => (s.linkToken?.mode === mode ? s.linkToken : null));
  const token = kept?.value ?? null;
  const held = useAuthStore((s) => s.linkSession);
  const lapsed = useAuthStore((s) => s.linkSessionLapsed);
  const [phase, setPhase] = useState<Phase>(token ? { name: 'resolving' } : { name: 'missing' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!token) {
      setPhase({ name: 'missing' });
      return;
    }
    let live = true;
    const show = (next: Phase) => {
      if (live) setPhase(next);
    };
    setPhase({ name: 'resolving' });
    void (async () => {
      try {
        const resolution = await resolveLink(token);
        if (!live) return;
        applyLinkLocale(resolution.locale);
        if (resolution.access_state === 'locked') return show({ name: 'gone', gone: 'locked' });
        if (resolution.access_state === 'verified' && resolution.link_session_id) {
          try {
            return show({ name: 'verified', session: await resumeLinkSession(resolution.link_session_id) });
          } catch (error) {
            const gone = goneOf(error);
            if (gone) return show({ name: 'gone', gone });
            // The session ended in between, or its answer was malformed: verify again.
          }
        }
        show({ name: 'verify' });
      } catch (error) {
        const gone = goneOf(error);
        show(gone ? { name: 'gone', gone } : { name: 'error', error });
      }
    })();
    return () => {
      live = false;
    };
    // `kept` changes whenever `token` does.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kept, attempt]);

  const actions = useMemo<GateActions>(
    () => ({
      gone: (gone) => {
        useAuthStore.getState().clearLinkSession();
        setPhase({ name: 'gone', gone });
      },
      done: () => setPhase({ name: 'done' }),
    }),
    [],
  );

  // The API ended the session (a 401 marks it lapsed), or another one replaced it: back to the code step. "Done"
  // clears the session without a lapse and moves on to its own page.
  const replaced = phase.name === 'verified' && held?.id !== phase.session.id && (lapsed || held !== null);
  const shown: Phase = replaced ? { name: 'verify' } : phase;
  const missing = <LinkState icon={Mail} title={t('recipient.missingTitle')} body={t('recipient.missingBody')} />;

  switch (shown.name) {
    case 'resolving':
      return (
        <Card className="text-center">
          <Shield className="mx-auto h-10 w-10 text-brand-600" aria-hidden="true" />
          <StepHeading>{t('recipient.title')}</StepHeading>
          <div className="mt-4 flex items-center justify-center gap-2 text-sm text-gray-600" role="status">
            <Spinner size="sm" />
            {t('recipient.resolving')}
          </div>
        </Card>
      );
    case 'gone':
      return <GonePage gone={shown.gone} />;
    case 'error':
      return (
        <LinkState icon={AlertCircle} title={t('recipient.errorTitle')} body={linkProblemText(shown.error, t)}>
          <Button className="mt-4" onClick={() => setAttempt((n) => n + 1)}>
            {t('common.tryAgain')}
          </Button>
        </LinkState>
      );
    case 'verify':
      if (!token) return missing;
      return (
        <VerificationPage
          mode={mode}
          token={token}
          lapsed={lapsed}
          onVerified={(session) => setPhase({ name: 'verified', session })}
          onGone={actions.gone}
        />
      );
    case 'missing':
      return missing;
    case 'verified':
      return <>{children(shown.session, actions)}</>;
    case 'done':
      return <LinkState icon={CheckCircle2} title={t('recipient.doneTitle')} body={t('recipient.doneBody')} />;
  }
}

const GONE_PAGES = {
  not_found: { icon: AlertCircle, title: 'recipient.notFoundTitle', body: 'recipient.notFoundBody' },
  revoked: { icon: AlertCircle, title: 'recipient.revokedTitle', body: 'recipient.revokedBody' },
  expired: { icon: Clock, title: 'recipient.expiredTitle', body: 'recipient.expiredBody' },
  locked: { icon: Lock, title: 'recipient.lockedTitle', body: 'recipient.lockedBody' },
} as const;

/** The not-found, revoked, expired and locked pages: each says what happened and what to do. */
export function GonePage({ gone }: { gone: LinkGone }) {
  const { t } = useTranslation();
  const page = GONE_PAGES[gone];
  return <LinkState icon={page.icon} title={t(page.title)} body={t(page.body)} testId={`link-${gone}`} />;
}

function LinkState({
  icon: Icon,
  title,
  body,
  children,
  testId,
}: {
  icon: typeof Mail;
  title: string;
  body: string;
  children?: ReactNode;
  testId?: string;
}) {
  return (
    <div data-testid={testId}>
      <Card className="text-center">
        <Icon className="mx-auto h-10 w-10 text-gray-500" aria-hidden="true" />
        <StepHeading>{title}</StepHeading>
        <p className="mt-2 text-sm text-gray-700">{body}</p>
        {children}
      </Card>
    </div>
  );
}
