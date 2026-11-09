import axios, { type AxiosError, type AxiosInstance, type InternalAxiosRequestConfig } from 'axios';

declare module 'axios' {
  interface AxiosRequestConfig {
    /** Never run step-up for this request: a `401 reauthentication_required` goes straight to the caller. */
    skipStepUp?: boolean;
    /** Set on the one retry after a step-up, so a second `reauthentication_required` is never retried (#232). */
    stepUpRetried?: boolean;
  }
}

/**
 * Step-up, retried once (#232; FR-35, authn-authz 3.3). A step-up operation (inviting a user, an API key, an audit
 * export, a DLP policy write, an approval, an SSO change and so on) answers `401 reauthentication_required` when the
 * member's sign-in is older than 15 minutes. Instead of failing, the one `apiClient` asks the page to confirm it's the
 * member (the "Confirm it's you" dialog signs in again in a popup and loads the new session), then sends the same
 * request again, once, with the new session's CSRF token. The page's form state is never touched: its call is still
 * waiting. When the member cancels, or no dialog is mounted (tests, the public pages), the original error goes back
 * to the page, which explains it (`AdminAccessNote`).
 */

/** Runs the step-up: resolves `true` once the new session is loaded and the request may be sent again. */
export type StepUpHandler = () => Promise<boolean>;

let handler: StepUpHandler | null = null;
let running: Promise<boolean> | null = null;

/** Mounts the step-up UI (the dialog). Returns a function that unmounts it, if it is still the one mounted. */
export function setStepUpHandler(next: StepUpHandler): () => void {
  handler = next;
  return () => {
    if (handler === next) handler = null;
  };
}

/**
 * Asks for a step-up. Requests that fail at the same time share one dialog and one sign-in. Resolves `false` without a
 * handler, on cancel, or when the handler fails.
 */
export function requestStepUp(): Promise<boolean> {
  if (!handler) return Promise.resolve(false);
  if (!running) {
    const current = handler;
    running = current()
      .catch(() => false)
      .finally(() => {
        running = null;
      });
  }
  return running;
}

/** What the interceptor needs to know about a failed request. */
export interface FailedRequest {
  status: number | undefined;
  code: string | undefined;
  /** The credential the request carried (`requestScope` in `@/lib/api`). */
  scope: 'member' | 'link' | 'public';
  skipStepUp?: boolean;
  stepUpRetried?: boolean;
}

/**
 * Whether a failed request gets a step-up and one retry: only a member request, only `401
 * reauthentication_required`, and only if it isn't already the retry.
 */
export function needsStepUp(request: FailedRequest): boolean {
  return (
    request.status === 401 &&
    request.code === 'reauthentication_required' &&
    request.scope === 'member' &&
    !request.skipStepUp &&
    !request.stepUpRetried
  );
}

function codeOf(data: unknown): string | undefined {
  if (typeof data === 'object' && data !== null && 'code' in data) {
    const { code } = data as { code: unknown };
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

/**
 * A `401` of a blob request (the audit export) arrives as a blob: it is read back into the problem document here, so
 * the code can be read, and the page sees the problem as for any other request.
 */
async function readBlobProblem(error: AxiosError): Promise<void> {
  const response = error.response;
  if (!response || response.status !== 401 || typeof Blob === 'undefined' || !(response.data instanceof Blob)) return;
  try {
    response.data = JSON.parse(await response.data.text());
  } catch {
    // Not JSON: no code, so no step-up.
  }
}

/**
 * The response interceptor `@/lib/api` installs on `apiClient`. `scopeOf` is its `requestScope`, passed in so this
 * module doesn't import the client it is installed on.
 */
export function stepUpInterceptor(client: AxiosInstance, scopeOf: (url: string | undefined) => FailedRequest['scope']) {
  return async (error: unknown): Promise<unknown> => {
    if (!axios.isAxiosError(error) || !error.config || error.response?.status !== 401) throw error;
    await readBlobProblem(error);
    const config: InternalAxiosRequestConfig = error.config;
    const retry = needsStepUp({
      status: error.response.status,
      code: codeOf(error.response.data),
      scope: scopeOf(config.url),
      skipStepUp: config.skipStepUp,
      stepUpRetried: config.stepUpRetried,
    });
    if (!retry || !(await requestStepUp())) throw error;
    // The same request again: the request interceptor puts the new session's CSRF token in place of the old one.
    return client.request({ ...config, stepUpRetried: true });
  };
}
