import { useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft } from 'lucide-react';
import { Alert, Button, Card, Input, toast } from '@/components/ui';
import type { DlpDetector, DlpPolicy } from '@/api';
import { createDlpDetector, invalidateDlp, updateDlpDetector, useDlpDetector, useDlpPolicy } from '@/hooks/dlp';
import { formatDate } from '@/lib/formatters';
import { IdempotencyKeys, mayHaveHappened } from '@/lib/idempotency';
import { failureOf, fieldErrors, problemCode } from '@/lib/problems';
import { ConfirmChange } from './ConfirmChange';
import { DetectorTestPanel } from './DetectorTestPanel';
import { LoadError, Loading } from './DlpAdminPage';
import {
  DETECTOR_NAME_MAX,
  detectorFieldErrors,
  emptyPatternForm,
  MAX_CONTEXT_KEYWORDS,
  MIN_LENGTH_EFFECTIVE_MAX,
  MIN_LENGTH_MAX,
  parseTerms,
  PATTERN_MAX,
  patternCreateBody,
  patternDraft,
  patternFormOf,
  patternProblems,
  patternUpdate,
  TERM_MAX,
  type PatternChange,
  type PatternField,
  type PatternForm,
} from './dlpForms';
import { useWrite } from './useWrite';

/** Each field's input, so a refusal from the service can move focus to the field it names. */
const FIELD_IDS: Record<PatternField, string> = {
  name: 'pattern-name',
  pattern: 'pattern-expression',
  context_keywords: 'pattern-context',
  min_length: 'pattern-min-length',
};

/**
 * A pattern's page (#221; FR-39, FR-56, detectors 5), new (`/admin/dlp/patterns/new`) or existing
 * (`/admin/dlp/patterns/:detectorId`): its name, an RE2 expression of at most 512 characters, context keywords one per
 * line (a match near one is more confident), whether case is ignored, and the shortest match that counts. The service
 * refuses an expression that doesn't compile, matches the empty string or is too complex, with a pointer to the field,
 * shown on it. A saved pattern shows how many files stopped it for taking too long (its scan-time budget), with advice
 * to narrow it. Under the form, "Test on sample text" tries the unsaved pattern.
 */
export function PatternEditor() {
  const { detectorId } = useParams<{ detectorId: string }>();
  const { t } = useTranslation();
  const detector = useDlpDetector(detectorId);
  const policy = useDlpPolicy();

  if (policy.isPending || (detectorId && detector.isPending)) return <Loading />;
  if (policy.isError) return <LoadError error={policy.error} />;
  if (detectorId && detector.isError) {
    return problemCode(detector.error) === 'not_found' ? <Alert>{t('dlpAdmin.patternNotFound')}</Alert> : <LoadError error={detector.error} />;
  }
  const existing = detectorId ? detector.data : undefined;
  if (existing && existing.kind !== 'pattern') return <Alert>{t('dlpAdmin.patternNotFound')}</Alert>;
  return <PatternFormView key={existing ? `${existing.id}:${existing.revision ?? 0}` : 'new'} detector={existing} policy={policy.data} />;
}

function PatternFormView({ detector, policy }: { detector: DlpDetector | undefined; policy: DlpPolicy }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<PatternForm>(() => (detector ? patternFormOf(detector) : emptyPatternForm));
  const [version] = useState(policy.version);
  const [shown, setShown] = useState(false);
  const [confirming, setConfirming] = useState(false);
  /** What the service refused, by field, until that field is edited again. */
  const [refused, setRefused] = useState<Partial<Record<PatternField, string>>>({});
  const write = useWrite();
  const keys = useRef(new IdempotencyKeys());

  const context = useMemo(() => parseTerms(form.context), [form.context]);
  const problems = patternProblems(form);
  const update = detector ? patternUpdate(detector, form, version) : null;
  const createBody = detector ? null : patternCreateBody(form, version);
  const nothingChanged = detector !== undefined && update !== null && update.changes.length === 0;
  const draft = useMemo(() => patternDraft(form), [form]);
  const nameOf = (id: string) => (id === 'draft' || id === detector?.id ? form.name.trim() || t('dlpAdmin.test.thisDraft') : id);

  const set = <K extends keyof PatternForm>(key: K, value: PatternForm[K], field?: PatternField) => {
    setForm((previous) => ({ ...previous, [key]: value }));
    if (field) setRefused((previous) => ({ ...previous, [field]: undefined }));
  };

  const lines = useMemo(() => {
    const name = form.name.trim();
    if (!detector) {
      return [
        t('dlpAdmin.change.addPattern', { name }),
        t('dlpAdmin.change.patternIs', { pattern: form.pattern }),
        ...(context.terms.length > 0 ? [t('dlpAdmin.change.context', { count: context.terms.length })] : []),
      ];
    }
    const describe = (change: PatternChange): string => {
      switch (change) {
        case 'name':
          return t('dlpAdmin.change.rename', { from: detector.name, to: name });
        case 'pattern':
          return t('dlpAdmin.change.patternIs', { pattern: form.pattern });
        case 'context_keywords':
          return t('dlpAdmin.change.context', { count: context.terms.length });
        case 'case_insensitive':
          return t(form.case_insensitive ? 'dlpAdmin.change.ignoreCase' : 'dlpAdmin.change.matchCase');
        case 'min_length':
          return t('dlpAdmin.change.minLength', { value: update?.body.min_length ?? 1 });
      }
    };
    return [t('dlpAdmin.change.editPattern', { name: detector.name }), ...(update?.changes ?? []).map(describe)];
  }, [detector, form, context.terms.length, update, t]);

  const submit = () => {
    setShown(true);
    if (Object.keys(problems).length > 0 || nothingChanged) return;
    write.reset();
    setConfirming(true);
  };

  const save = async () => {
    let failed: unknown = null;
    const ok = await write.run(async () => {
      try {
        if (detector && update) {
          await updateDlpDetector(detector.id, update.body);
        } else if (createBody) {
          try {
            await createDlpDetector(createBody, keys.current.keyForBody('createDlpDetector', createBody));
            keys.current.done('createDlpDetector');
          } catch (failure) {
            if (!mayHaveHappened(failure)) keys.current.done('createDlpDetector');
            throw failure;
          }
        }
      } catch (failure) {
        failed = failure;
        throw failure;
      }
      await invalidateDlp(queryClient);
    });
    if (ok) {
      setConfirming(false);
      toast('success', t(detector ? 'dlpAdmin.patternSaved' : 'dlpAdmin.patternAdded', { name: form.name.trim() }));
      navigate('/admin/dlp/keywords');
      return;
    }
    // A refusal with a pointer goes on its field, and focus with it; anything else stays in the dialog.
    if (problemCode(failed) !== 'validation_failed') return;
    const { byField } = detectorFieldErrors(fieldErrors(failureOf(failed)));
    const fields = (Object.keys(FIELD_IDS) as PatternField[]).filter((field) => byField[field]);
    if (fields.length === 0) return;
    setRefused(Object.fromEntries(fields.map((field) => [field, byField[field]])));
    setConfirming(false);
    write.reset();
    requestAnimationFrame(() => document.getElementById(FIELD_IDS[fields[0] as PatternField])?.focus());
  };

  const fieldError = (field: PatternField): string | undefined => {
    if (refused[field]) return t('dlpAdmin.refused', { detail: refused[field] });
    if (!shown || !problems[field]) return undefined;
    return t(`dlpAdmin.patternProblem.${problems[field]}`, {
      max: field === 'pattern' ? PATTERN_MAX : field === 'min_length' ? MIN_LENGTH_MAX : MAX_CONTEXT_KEYWORDS,
      length: TERM_MAX,
      count: context.tooLong.length,
    });
  };
  const contextError = fieldError('context_keywords');
  const stops = detector?.budget_exceeded_files ?? 0;

  return (
    <>
      <form
        className="mx-auto max-w-2xl space-y-6"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-gray-900">{detector ? t('dlpAdmin.editPattern') : t('dlpAdmin.addPattern')}</h2>
          <Link to="/admin/dlp/keywords" className="btn-secondary">
            <ArrowLeft className="mr-2 h-4 w-4" aria-hidden="true" />
            {t('dlpAdmin.backToKeywordLists')}
          </Link>
        </div>

        {stops > 0 && (
          <Alert variant="warning" role="status">
            <p>
              {detector?.budget_exceeded_last_at
                ? t('dlpAdmin.budgetStops', { count: stops, date: formatDate(detector.budget_exceeded_last_at, i18n.language) })
                : t('dlpAdmin.budgetStopsNoDate', { count: stops })}
            </p>
            <p className="mt-1">{t('dlpAdmin.budgetAdvice')}</p>
          </Alert>
        )}

        <Card>
          <div className="space-y-4">
            <Input
              id={FIELD_IDS.name}
              label={t('common.name')}
              value={form.name}
              maxLength={DETECTOR_NAME_MAX}
              onChange={(event) => set('name', event.target.value, 'name')}
              error={fieldError('name')}
            />
            <div className="space-y-1.5">
              <Input
                id={FIELD_IDS.pattern}
                label={t('dlpAdmin.pattern')}
                className="font-mono"
                value={form.pattern}
                spellCheck={false}
                autoComplete="off"
                autoCapitalize="off"
                placeholder="INV-[0-9]{6}"
                onChange={(event) => set('pattern', event.target.value, 'pattern')}
                error={fieldError('pattern')}
                helperText={t('dlpAdmin.patternHint', { max: PATTERN_MAX })}
              />
              <p className="text-right text-xs text-gray-500" aria-live="polite">
                {t('dlpAdmin.patternLength', { count: [...form.pattern].length, max: PATTERN_MAX })}
              </p>
            </div>
            <div className="space-y-1.5">
              <label htmlFor={FIELD_IDS.context_keywords} className="block text-sm font-medium text-gray-700">
                {t('dlpAdmin.contextKeywords')}
              </label>
              <textarea
                id={FIELD_IDS.context_keywords}
                className="input-field min-h-[120px] resize-y"
                value={form.context}
                spellCheck={false}
                aria-invalid={contextError ? true : undefined}
                aria-describedby={contextError ? 'pattern-context-error pattern-context-hint' : 'pattern-context-hint'}
                onChange={(event) => set('context', event.target.value, 'context_keywords')}
              />
              {contextError && (
                <p id="pattern-context-error" className="text-sm text-red-600">
                  {contextError}
                </p>
              )}
              <p id="pattern-context-hint" className="text-sm text-gray-500">
                {t('dlpAdmin.contextKeywordsHint', { max: MAX_CONTEXT_KEYWORDS, length: TERM_MAX })}
              </p>
              <p className="text-sm text-gray-700" aria-live="polite">
                {t('dlpAdmin.contextCount', { count: context.terms.length, max: MAX_CONTEXT_KEYWORDS })}
              </p>
            </div>
            <label className="flex items-start gap-3">
              <input
                type="checkbox"
                className="mt-1 h-4 w-4 accent-brand-600"
                checked={form.case_insensitive}
                onChange={(event) => set('case_insensitive', event.target.checked)}
              />
              <span>
                <span className="block text-sm font-medium text-gray-900">{t('dlpAdmin.caseInsensitive')}</span>
                <span className="block text-sm text-gray-600">{t('dlpAdmin.caseInsensitiveHint')}</span>
              </span>
            </label>
            <Input
              id={FIELD_IDS.min_length}
              label={t('dlpAdmin.minLength')}
              inputMode="numeric"
              value={form.min_length}
              onChange={(event) => set('min_length', event.target.value, 'min_length')}
              error={fieldError('min_length')}
              helperText={t('dlpAdmin.minLengthHint', { max: MIN_LENGTH_MAX.toLocaleString(), effective: MIN_LENGTH_EFFECTIVE_MAX })}
            />
          </div>
        </Card>

        {nothingChanged && shown && (
          <Alert variant="info" role="status">
            {t('dlpAdmin.nothingChanged')}
          </Alert>
        )}

        <Button type="submit" className="w-full">
          {detector ? t('common.save') : t('dlpAdmin.addPattern')}
        </Button>
      </form>

      <div className="mx-auto mt-6 max-w-2xl">
        <DetectorTestPanel existingId={detector?.id ?? null} changed={!nothingChanged} draft={draft} nameOf={nameOf} />
      </div>

      <ConfirmChange
        open={confirming}
        title={detector ? t('dlpAdmin.confirmEditPattern') : t('dlpAdmin.confirmAddPattern')}
        lines={lines}
        action={detector ? t('common.save') : t('dlpAdmin.addPattern')}
        busy={write.busy}
        error={write.error}
        onConfirm={() => void save()}
        onClose={() => setConfirming(false)}
        onReload={() => {
          setConfirming(false);
          void invalidateDlp(queryClient);
        }}
      />
    </>
  );
}
