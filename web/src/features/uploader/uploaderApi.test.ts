import { afterEach, describe, expect, it, vi } from 'vitest';
import type { InternalAxiosRequestConfig } from 'axios';
import type { FileState } from '@/api';
import i18n, { resources } from '@/lib/i18n';
import { csrfToken, header, problem, setUpApi, type FakeReply } from '@/test/apiHarness';
import { useAuthStore } from '@/stores/authStore';
import { createStorageClient, FileUpload } from '@/features/sender/upload';
import {
  addSessionUploadFile,
  countedFiles,
  deleteSessionUploadFile,
  IDLE_POLL_MS,
  limitsOf,
  resumableMatch,
  sessionUploadApi,
  uploaderFileProblem,
  uploaderFileStatus,
  uploaderMayRemove,
  uploaderProblemText,
  uploaderStatusVariant,
  uploadsPollInterval,
  UPLOADS_POLL_MS,
  type SessionFile,
} from './uploaderApi';

const sessionId = '0190c0de-0000-7000-8000-0000000000e2';
const fileId = '0190c0de-0000-7000-8000-0000000000f2';
const MIB = 1024 * 1024;
const FILE_STATES: FileState[] = [
  'uploading',
  'completing',
  'scanning',
  'clean',
  'infected',
  'unscannable',
  'scan_failed',
  'rejected',
  'deleted',
];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('what the uploader sees of a file (#213, FR-12)', () => {
  it('a blocked file says only "blocked by the company\'s policy" or "couldn\'t be scanned"', () => {
    expect(uploaderFileStatus('infected')).toBe('blocked');
    expect(uploaderFileStatus('unscannable')).toBe('unscannable');
    expect(uploaderFileStatus('scan_failed')).toBe('unscannable');
    expect(resources.en.translation.uploader.status.blocked).toBe('Blocked by the company\'s policy');
    expect(resources.en.translation.uploader.status.unscannable).toBe('Couldn\'t be scanned');
  });

  it('maps every FileState to a status with a badge and a label in both languages, and never names a finding', () => {
    for (const state of FILE_STATES) {
      const status = uploaderFileStatus(state);
      expect(uploaderStatusVariant[status], state).toBeTruthy();
      for (const language of ['en', 'ja'] as const) {
        const label = resources[language].translation.uploader.status[status];
        expect(label, `${language}: ${status}`).toBeTruthy();
        expect(label.toLowerCase()).not.toMatch(/malware|virus|infected|eicar|my number|マルウェア|ウイルス/);
      }
    }
    expect(resources.en.translation.uploader.status.waiting).toBeTruthy();
  });

  it('polls fast while this tab uploads or the service moves a file, else slowly so a revocation shows', () => {
    expect(uploadsPollInterval([], true)).toBe(UPLOADS_POLL_MS);
    expect(uploadsPollInterval([{ state: 'scanning' }], false)).toBe(UPLOADS_POLL_MS);
    expect(uploadsPollInterval([{ state: 'clean' }], false)).toBe(IDLE_POLL_MS);
    expect(uploadsPollInterval(undefined, false)).toBe(IDLE_POLL_MS);
  });
});

describe('the request\'s limits before anything is sent (#213, FR-11)', () => {
  const limits = limitsOf({ max_files: 3, max_file_size: 100, max_total_size: 250 });

  it('checks the size of each file, the number of files and the total', () => {
    expect(uploaderFileProblem(0, [], limits)).toBe('empty');
    expect(uploaderFileProblem(101, [], limits)).toBe('too_large');
    expect(uploaderFileProblem(10, [1, 1, 1], limits)).toBe('too_many');
    expect(uploaderFileProblem(100, [100, 60], limits)).toBe('total_too_large');
    expect(uploaderFileProblem(90, [100, 60], limits)).toBeNull();
  });

  it('counts every declared file but a rejected or removed one', () => {
    const files = [{ state: 'uploading' }, { state: 'clean' }, { state: 'rejected' }, { state: 'deleted' }, { state: 'infected' }] as const;
    expect(countedFiles(files).map((file) => file.state)).toEqual(['uploading', 'clean', 'infected']);
  });

  it('matches a picked file to one still uploading, by name and size, once', () => {
    const files = [
      { id: 'a', display_name: 'contract.pdf', size: 10, state: 'clean' },
      { id: 'b', display_name: 'contract.pdf', size: 10, state: 'uploading' },
      { id: 'c', display_name: 'contract.pdf', size: 11, state: 'uploading' },
    ] satisfies Pick<SessionFile, 'id' | 'display_name' | 'size' | 'state'>[];
    expect(resumableMatch({ name: 'contract.pdf', size: 10 }, files, new Set())?.id).toBe('b');
    expect(resumableMatch({ name: 'contract.pdf', size: 10 }, files, new Set(['b']))).toBeNull();
    expect(resumableMatch({ name: 'other.pdf', size: 10 }, files, new Set())).toBeNull();
  });

  it('words the limit problems for the uploader, and the rest as the link pages do', () => {
    const t = i18n.getFixedT('en');
    const failure = (status: number, code: string) =>
      Object.assign(new Error(code), {
        isAxiosError: true,
        response: { status, data: problem(status, code).data, headers: {} },
      });
    expect(uploaderProblemText(failure(422, 'too_many_files'), t)).toBe(resources.en.translation.uploader.problems.too_many_files);
    expect(uploaderProblemText(failure(422, 'code_expired'), t)).toBe(resources.en.translation.recipient.problems.code_expired);
  });
});

describe('the uploader\'s upload through the M3 engine (#213)', () => {
  /** Answers the session's upload operations, and records what was sent. */
  function sessionApi(held: number[] = []) {
    const plan = { part_size: 5 * MIB, part_count: 2 };
    const replies = (config: InternalAxiosRequestConfig): FakeReply => {
      const route = `${config.method?.toUpperCase()} ${config.url}`;
      if (route === `GET /session/files/${fileId}/parts`) {
        return { status: 200, data: { ...plan, parts: held.map((n) => ({ part_number: n, size: n === 1 ? 5 * MIB : 1000 })) } };
      }
      if (route === `POST /session/files/${fileId}/parts`) {
        const numbers = JSON.parse(String(config.data)).part_numbers as number[];
        return {
          status: 200,
          data: {
            parts: numbers.map((n) => ({
              part_number: n,
              size: n === 1 ? 5 * MIB : 1000,
              method: 'PUT',
              url: `https://files.example/bucket/key?partNumber=${n}`,
              expires_at: '2999-01-01T00:00:00Z',
            })),
          },
        };
      }
      if (route === `POST /session/files/${fileId}/complete`) return { status: 200, data: { id: fileId, state: 'scanning' } };
      if (route === 'POST /session/files') return { status: 201, data: { id: fileId, state: 'uploading', upload: plan } };
      return problem(404, 'not_found');
    };
    return replies;
  }

  function storage() {
    const client = createStorageClient();
    const parts: number[] = [];
    const headers: unknown[] = [];
    client.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      parts.push(Number(new URL(config.url ?? '').searchParams.get('partNumber')));
      headers.push(config.headers);
      return { status: 200, statusText: 'OK', data: '', headers: {}, config };
    };
    return { client, parts, headers };
  }

  it('declares the file with an Idempotency-Key, in the link session, with its CSRF token', async () => {
    const { sent } = await setUpApi(sessionApi());
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    await addSessionUploadFile({ display_name: 'contract.pdf', size: 5 * MIB + 1000 }, 'key-1');
    expect(sent[0]?.url).toBe('/session/files');
    expect(header(sent[0], 'Idempotency-Key')).toBe('key-1');
    expect(header(sent[0], 'X-Link-Session')).toBe(sessionId);
    expect(header(sent[0], 'X-CSRF-Token')).toBe(csrfToken('link'));
  });

  it('lists the parts, asks for URLs, puts each part to storage and completes, all through the session', async () => {
    const { sent } = await setUpApi(sessionApi());
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    const store = storage();
    const blob = new Blob([new Uint8Array(5 * MIB + 1000)]);
    const upload = new FileUpload({ fileId, blob, api: sessionUploadApi, storage: store.client });
    const completed = await upload.start();
    expect(completed).toMatchObject({ id: fileId, state: 'scanning' });
    expect(sent.map((config) => `${config.method?.toUpperCase()} ${config.url}`)).toEqual([
      `GET /session/files/${fileId}/parts`,
      `POST /session/files/${fileId}/parts`,
      `POST /session/files/${fileId}/complete`,
    ]);
    for (const config of sent) expect(header(config, 'X-Link-Session')).toBe(sessionId);
    expect(header(sent[0], 'X-CSRF-Token')).toBeUndefined();
    expect(header(sent[1], 'X-CSRF-Token')).toBe(csrfToken('link'));
    expect(header(sent[2], 'X-CSRF-Token')).toBe(csrfToken('link'));
    expect(store.parts.sort()).toEqual([1, 2]);
    // Nothing of the link session reaches storage.
    for (const headers of store.headers) expect(JSON.stringify(headers)).not.toMatch(/X-Link-Session|X-CSRF-Token/i);
  });

  it('resumes after a reload without sending again a part storage already holds (FR-11)', async () => {
    const { sent } = await setUpApi(sessionApi([1]));
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    const store = storage();
    const blob = new Blob([new Uint8Array(5 * MIB + 1000)]);
    await new FileUpload({ fileId, blob, api: sessionUploadApi, storage: store.client }).start();
    expect(store.parts).toEqual([2]);
    expect(JSON.parse(String(sent[1]?.data))).toEqual({ part_numbers: [2] });
  });

  it('gives the engine no delete: cancelling only stops the parts, and the page removes a file itself', () => {
    expect('deleteFile' in sessionUploadApi).toBe(false);
  });
});

describe('an allowed unscannable file, and taking a file back (#229)', () => {
  it('words an unscannable file the company accepted as accepted, in both languages', () => {
    expect(uploaderFileStatus('unscannable', 'unscannable')).toBe('accepted');
    expect(uploaderFileStatus('unscannable')).toBe('unscannable');
    expect(uploaderFileStatus('scan_failed', 'unscannable')).toBe('unscannable');
    expect(uploaderStatusVariant.accepted).toBe('success');
    for (const language of ['en', 'ja'] as const) {
      const words = resources[language].translation.uploader;
      expect(words.status.accepted).toBeTruthy();
      expect(words.acceptedHint).toBeTruthy();
      expect(words.status.accepted).not.toBe(words.status.unscannable);
    }
  });

  it('offers removal for every file but a blocked or deleted one', () => {
    const removable = FILE_STATES.filter((state) => uploaderMayRemove({ state }));
    expect(removable).toEqual(['uploading', 'completing', 'scanning', 'clean', 'rejected']);
    expect(uploaderMayRemove({ state: 'unscannable', warning: 'unscannable' })).toBe(true);
    expect(uploaderMayRemove({ state: 'unscannable' })).toBe(false);
  });

  it('words any file the API marks blocked as "not accepted", with no reason, and never offers to remove it (#221, FR-51)', () => {
    for (const state of ['clean', 'infected', 'scan_failed', 'unscannable'] as const) {
      expect(uploaderFileStatus(state, undefined, true), state).toBe('notAccepted');
      expect(uploaderMayRemove({ state, blocked: true }), state).toBe(false);
    }
    expect(uploaderFileStatus('unscannable', 'unscannable', true)).toBe('notAccepted');
    expect(uploaderFileStatus('deleted', undefined, true)).toBe('removed');
    expect(uploaderFileStatus('clean', undefined, false)).toBe('received');
    expect(uploaderStatusVariant.notAccepted).toBe('danger');
    for (const language of ['en', 'ja'] as const) {
      const words = resources[language].translation.uploader;
      expect(words.status.notAccepted).toBeTruthy();
      expect(`${words.status.notAccepted} ${words.notAcceptedHint}`.toLowerCase()).not.toMatch(
        /malware|virus|infected|data loss|dlp|my number|マルウェア|ウイルス|情報漏えい/,
      );
    }
  });

  it('removes the file through the link session, with its CSRF token', async () => {
    const { sent } = await setUpApi((config) =>
      config.method === 'delete' && config.url === `/session/files/${fileId}` ? { status: 204, data: '' } : problem(404, 'not_found'),
    );
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    await deleteSessionUploadFile(fileId);
    expect(sent).toHaveLength(1);
    expect(header(sent[0], 'X-Link-Session')).toBe(sessionId);
    expect(header(sent[0], 'X-CSRF-Token')).toBe(csrfToken('link'));
  });

  it('words a blocked file\'s refusal as the link pages do', async () => {
    await setUpApi(() => problem(409, 'invalid_state'));
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    const error = await deleteSessionUploadFile(fileId).catch((caught: unknown) => caught);
    await i18n.changeLanguage('en');
    expect(uploaderProblemText(error, i18n.t)).toBeTruthy();
  });
});
