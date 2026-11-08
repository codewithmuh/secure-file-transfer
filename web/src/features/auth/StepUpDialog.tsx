import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Dialog, Spinner } from '@/components/ui';
import { setStepUpHandler } from '@/lib/stepUp';
import { useAuthStore, type Member } from '@/stores/authStore';
import { refreshMemberSession } from './memberSession';
import { isStepUpMessage, STEP_UP_COMPLETE_PATH, stepUpOutcome, stepUpSignIn, stepUpSignInUrl } from './stepUp';

/**
 * - `ask`: the dialog says why, before anything opens (a popup needs the member's click).
 * - `waiting`: the popup is open; the page waits for its message.
 * - `windowClosed`: the popup closed without a message (closed by hand, or cut off from this window).
 * - `blocked`: the browser refused the popup; the only way left is a sign-in on this page.
 * - `finishing`: the popup said it's done; the new session is loading, then the request goes again.
 * - `failed`: the new session couldn't be loaded.
 */
type Phase = 'closed' | 'ask' | 'waiting' | 'windowClosed' | 'blocked' | 'finishing' | 'failed';

const POPUP_NAME = 'sft-step-up';
const POPUP_FEATURES = 'popup=yes,width=520,height=720';
const POPUP_POLL_MS = 500;

/**
 * "Confirm it's you" (#232; FR-35, authn-authz 3.3): the one dialog for every step-up operation. `apiClient` opens it
 * on `401 reauthentication_required` (`@/lib/stepUp`). The member signs in again the same way in as before (SSO
 * through their identity provider, else local) in a popup, which lands on `/auth/step-up-complete` and posts one
 * message back. The dialog checks that message's origin, its type and the window it came from, loads the new session
 * (the old one is revoked, so its CSRF token is stale), and lets the request go again, once. The page and its form
 * never unmount. If the browser blocks the popup, the member can sign in on this page instead, and sends their change
 * again afterwards. Mounted once, in `Providers`.
 */
export function StepUpDialog() {
  const { t } = useTranslation();
  const [phase, setPhase] = useState<Phase>('closed');
  const resolver = useRef<((ok: boolean) => void) | null>(null);
  const popup = useRef<Window | null>(null);
  const before = useRef<Member | null>(null);
  const primary = useRef<HTMLButtonElement>(null);

  const settle = useCallback((ok: boolean) => {
    const resolve = resolver.current;
    resolver.current = null;
    popup.current = null;
    setPhase('closed');
    resolve?.(ok);
  }, []);

  const cancel = useCallback(() => {
    try {
      popup.current?.close();
    } catch {
      // Already gone.
    }
    settle(false);
  }, [settle]);

  useEffect(() => {
    const unmount = setStepUpHandler(
      () =>
        new Promise<boolean>((resolve) => {
          resolver.current = resolve;
          before.current = useAuthStore.getState().user;
          setPhase('ask');
        }),
    );
    return () => {
      unmount();
      resolver.current?.(false);
      resolver.current = null;
    };
  }, []);

  // The popup's one message, while it may still come.
  useEffect(() => {
    if (phase !== 'waiting' && phase !== 'windowClosed') return;
    const onMessage = (event: MessageEvent) => {
      if (!isStepUpMessage(event, window.location.origin)) return;
      if (popup.current && event.source !== popup.current) return;
      setPhase('finishing');
      void refreshMemberSession().then((after) => {
        switch (stepUpOutcome(before.current, after)) {
          case 'retry':
            settle(true);
            break;
          case 'other_member':
            // Someone else signed in: nothing of the first member's is sent; the app starts again as the new member.
            settle(false);
            window.location.assign('/');
            break;
          case 'failed':
            setPhase('failed');
            break;
        }
      });
    };
    window.addEventListener('message', onMessage);
    const timer =
      phase === 'waiting'
        ? window.setInterval(() => {
            if (popup.current?.closed) setPhase('windowClosed');
          }, POPUP_POLL_MS)
        : undefined;
    return () => {
      window.removeEventListener('message', onMessage);
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, [phase, settle]);

  // Escape cancels the step-up only, never a dialog of the page underneath, which still waits for its request.
  useEffect(() => {
    if (phase === 'closed') return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      event.stopPropagation();
      if (phase !== 'finishing') cancel();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [phase, cancel]);

  // Each step's main button takes the focus, so a keyboard user is never left on a button that went away.
  useEffect(() => {
    if (phase !== 'closed') primary.current?.focus();
  }, [phase]);

  const openPopup = () => {
    const opened = window.open(stepUpSignInUrl(before.current, STEP_UP_COMPLETE_PATH), POPUP_NAME, POPUP_FEATURES);
    if (!opened) {
      setPhase('blocked');
      return;
    }
    popup.current = opened;
    setPhase('waiting');
  };

  const signInHere = () => {
    window.location.assign(stepUpSignInUrl(before.current, `${window.location.pathname}${window.location.search}`));
  };

  const sso = stepUpSignIn(before.current).method === 'sso';
  const busy = phase === 'finishing';

  let text: string;
  switch (phase) {
    case 'waiting':
      text = t('stepUp.waiting');
      break;
    case 'windowClosed':
      text = t('stepUp.windowClosed');
      break;
    case 'blocked':
      text = t('stepUp.blocked');
      break;
    case 'finishing':
      text = t('stepUp.finishing');
      break;
    case 'failed':
      text = t('stepUp.failed');
      break;
    default:
      text = t(sso ? 'stepUp.bodySso' : 'stepUp.body');
  }

  return (
    <Dialog open={phase !== 'closed'} onClose={busy ? () => undefined : cancel} title={t('stepUp.title')}>
      <div aria-live="polite" className="flex items-start gap-3 text-sm text-gray-700">
        {busy && <Spinner size="sm" className="mt-0.5 shrink-0" />}
        <p>{text}</p>
      </div>
      {(phase === 'windowClosed' || phase === 'failed') && (
        <p className="mt-3 text-sm text-gray-600">{t('stepUp.samePageHint')}</p>
      )}
      <div className="mt-6 flex flex-wrap justify-end gap-3">
        <Button type="button" variant="secondary" onClick={cancel} disabled={busy}>
          {t('common.cancel')}
        </Button>
        {(phase === 'windowClosed' || phase === 'failed') && (
          <Button type="button" variant="secondary" onClick={signInHere}>
            {t('stepUp.samePage')}
          </Button>
        )}
        {phase === 'blocked' ? (
          <Button ref={primary} type="button" onClick={signInHere}>
            {t('stepUp.samePage')}
          </Button>
        ) : phase === 'waiting' ? (
          <Button ref={primary} type="button" onClick={openPopup}>
            {t('stepUp.openAgain')}
          </Button>
        ) : (
          <Button ref={primary} type="button" onClick={openPopup} loading={busy}>
            {t(phase === 'ask' ? 'stepUp.signIn' : 'common.tryAgain')}
          </Button>
        )}
      </div>
    </Dialog>
  );
}
