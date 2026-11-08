import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { FlaskConical } from 'lucide-react';
import { Alert, Button, Card, CardTitle, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui';
import { testDlpDetectors, type DlpDetectorCreate, type DlpDetectorTestResult } from '@/hooks/dlp';
import { errorMessage, failureOf, fieldErrors } from '@/lib/problems';
import { detectorFieldErrors, detectorTestBody, TEST_TEXT_MAX } from './dlpForms';

export interface DetectorTestPanelProps {
  /** The saved detector's ID, tested as it is while the form is unchanged; `null` on a new one. */
  existingId: string | null;
  /** Whether the form differs from what is saved: then the draft is tested instead. */
  changed: boolean;
  /** The form as a draft definition, or `null` while it has problems. */
  draft: DlpDetectorCreate | null;
  /** A detector's name for a result row: `draft` is the form's own. */
  nameOf: (detector: string) => string;
}

/**
 * "Test on sample text" (#221; FR-56), under a keyword list's or a pattern's form: up to 16,384 characters of text,
 * the unsaved draft (or the saved detector while nothing changed) run on it by `testDlpDetectors`, and what it finds,
 * by line and confidence, masked as findings are. The text is processed in memory by the service, never stored or
 * logged, and the page keeps it only while it is open. At most 30 tests a minute (`429`).
 */
export function DetectorTestPanel({ existingId, changed, draft, nameOf }: DetectorTestPanelProps) {
  const { t } = useTranslation();
  const id = useId();
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<DlpDetectorTestResult | null>(null);

  const length = [...text].length;
  const tooLong = length > TEST_TEXT_MAX;
  const body = detectorTestBody(text, existingId, changed, draft);
  const what = existingId && !changed ? 'saved' : draft ? 'draft' : 'incomplete';
  const textId = `${id}-text`;
  const countId = `${id}-count`;
  const noteId = `${id}-note`;
  const errorId = `${id}-error`;

  const run = async () => {
    if (!body) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await testDlpDetectors(body));
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardTitle>{t('dlpAdmin.test.title')}</CardTitle>
      <p className="mt-2 text-sm text-gray-600">{t('dlpAdmin.test.hint')}</p>
      <div className="mt-4 space-y-1.5">
        <label htmlFor={textId} className="block text-sm font-medium text-gray-700">
          {t('dlpAdmin.test.text')}
        </label>
        <textarea
          id={textId}
          className="input-field min-h-[160px] resize-y font-mono"
          value={text}
          spellCheck={false}
          autoComplete="off"
          aria-invalid={tooLong ? true : undefined}
          aria-describedby={[tooLong ? errorId : null, countId, noteId].filter(Boolean).join(' ')}
          onChange={(event) => setText(event.target.value)}
        />
        {tooLong && (
          <p id={errorId} className="text-sm text-red-600">
            {t('dlpAdmin.test.tooLong', { max: TEST_TEXT_MAX.toLocaleString() })}
          </p>
        )}
        <p id={countId} className="text-right text-xs text-gray-500" aria-live="polite">
          {t('dlpAdmin.test.count', { count: length, max: TEST_TEXT_MAX.toLocaleString() })}
        </p>
        <p id={noteId} className="text-sm text-gray-600">
          {t('dlpAdmin.test.notSaved')} {t(`dlpAdmin.test.what.${what}`)}
        </p>
      </div>
      <div className="mt-4">
        <Button type="button" variant="secondary" loading={busy} disabled={!body} onClick={() => void run()}>
          <FlaskConical className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('dlpAdmin.test.run')}
        </Button>
      </div>

      {error !== null && <TestError error={error} />}

      {result && (
        <div className="mt-4">
          <p role="status" className="text-sm font-medium text-gray-900">
            {result.matches.length === 0 ? t('dlpAdmin.test.noMatches') : t('dlpAdmin.test.matches', { count: result.matches.length })}
          </p>
          {result.truncated && <p className="mt-1 text-sm text-gray-600">{t('dlpAdmin.test.truncated')}</p>}
          {result.matches.length > 0 && (
            <Table label={t('dlpAdmin.test.results')} caption={t('dlpAdmin.test.resultsCaption')} className="mt-3">
              <TableHead>
                <tr>
                  <TableHeader>{t('dlpAdmin.test.detector')}</TableHeader>
                  <TableHeader>{t('dlpAdmin.test.line')}</TableHeader>
                  <TableHeader>{t('dlpAdmin.test.confidence')}</TableHeader>
                  <TableHeader>{t('dlpAdmin.test.preview')}</TableHeader>
                </tr>
              </TableHead>
              <TableBody>
                {result.matches.map((match, index) => (
                  <TableRow key={`${match.detector}:${match.line}:${index}`}>
                    <TableCell className="whitespace-normal">{nameOf(match.detector)}</TableCell>
                    <TableCell>{match.line}</TableCell>
                    <TableCell>{t(`dlpAdmin.confidence.${match.confidence}`)}</TableCell>
                    <TableCell>
                      <code className="break-all text-xs">{match.preview}</code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      )}
    </Card>
  );
}

/** A failed test: too much text (`413`), too many tests (`429`, with the wait), a draft the service refused (`422`). */
function TestError({ error }: { error: unknown }) {
  const { t } = useTranslation();
  const failure = failureOf(error);
  let lines: string[];
  if (failure.status === 413) {
    lines = [t('dlpAdmin.test.tooLarge', { max: TEST_TEXT_MAX.toLocaleString() })];
  } else if (failure.status === 429) {
    const wait = failure.retryAfter !== null ? ` ${t('problems.retryAfter', { count: failure.retryAfter })}` : '';
    lines = [`${t('dlpAdmin.test.rateLimited')}${wait}`];
  } else if (failure.status === 422) {
    const { byField, other } = detectorFieldErrors(fieldErrors(failure));
    const details = [...Object.values(byField), ...other];
    lines = details.length > 0 ? details.map((detail) => t('dlpAdmin.test.refused', { detail })) : [errorMessage(error, t)];
  } else {
    lines = [errorMessage(error, t)];
  }
  return (
    <Alert className="mt-4">
      {lines.map((line, index) => (
        <p key={index}>{line}</p>
      ))}
    </Alert>
  );
}
