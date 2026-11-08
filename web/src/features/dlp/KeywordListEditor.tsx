import { useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft } from 'lucide-react';
import { Alert, Button, Card, Input, toast } from '@/components/ui';
import type { DlpDetector, DlpPolicy } from '@/api';
import { createDlpDetector, invalidateDlp, updateDlpDetector, useDlpDetector, useDlpPolicy } from '@/hooks/dlp';
import { IdempotencyKeys, mayHaveHappened } from '@/lib/idempotency';
import { problemCode } from '@/lib/problems';
import { ConfirmChange } from './ConfirmChange';
import { LoadError, Loading } from './DlpAdminPage';
import {
  DETECTOR_NAME_MAX,
  keywordCreateBody,
  keywordFormOf,
  keywordProblems,
  keywordUpdate,
  MAX_TERMS,
  parseTerms,
  TERM_MAX,
  type KeywordForm,
} from './dlpForms';
import { useWrite } from './useWrite';

/**
 * A keyword list's page (#218; FR-38, detectors 5): its name and its terms, one per line, 1 to 1,000 terms of 1 to
 * 100 characters. Terms match in any width and case, and Japanese terms without word boundaries. This is the only
 * page that shows the terms.
 */
export function KeywordListEditor() {
  const { detectorId } = useParams<{ detectorId: string }>();
  const { t } = useTranslation();
  const detector = useDlpDetector(detectorId);
  const policy = useDlpPolicy();

  if (policy.isPending || (detectorId && detector.isPending)) return <Loading />;
  if (policy.isError) return <LoadError error={policy.error} />;
  if (detectorId && detector.isError) {
    return problemCode(detector.error) === 'not_found' ? <Alert>{t('dlpAdmin.keywordListNotFound')}</Alert> : <LoadError error={detector.error} />;
  }
  const existing = detectorId ? detector.data : undefined;
  if (existing && existing.kind !== 'keywords') return <Alert>{t('dlpAdmin.keywordListNotFound')}</Alert>;
  return <KeywordFormView key={existing ? `${existing.id}:${existing.revision ?? 0}` : 'new'} detector={existing} policy={policy.data} />;
}

function KeywordFormView({ detector, policy }: { detector: DlpDetector | undefined; policy: DlpPolicy }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<KeywordForm>(() => (detector ? keywordFormOf(detector) : { name: '', terms: '' }));
  const [version] = useState(policy.version);
  const [shown, setShown] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const write = useWrite();
  const keys = useRef(new IdempotencyKeys());

  const parsed = useMemo(() => parseTerms(form.terms), [form.terms]);
  const problems = keywordProblems(form);
  const update = detector ? keywordUpdate(detector, form, version) : null;
  const createBody = detector ? null : keywordCreateBody(form, version);
  const nothingChanged = detector !== undefined && update !== null && update.changes.length === 0;

  const lines = useMemo(() => {
    const name = form.name.trim();
    if (!detector) return [t('dlpAdmin.change.addKeywordList', { name, count: parsed.terms.length })];
    const out = [t('dlpAdmin.change.editKeywordList', { name: detector.name })];
    if (update?.changes.includes('name')) out.push(t('dlpAdmin.change.rename', { from: detector.name, to: name }));
    if (update?.changes.includes('terms')) {
      out.push(t('dlpAdmin.change.terms', { added: update.added, removed: update.removed, count: parsed.terms.length }));
    }
    return out;
  }, [detector, form.name, parsed.terms.length, update, t]);

  const submit = () => {
    setShown(true);
    if (Object.keys(problems).length > 0 || nothingChanged) return;
    write.reset();
    setConfirming(true);
  };

  const save = async () => {
    const ok = await write.run(async () => {
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
      await invalidateDlp(queryClient);
    });
    if (ok) {
      setConfirming(false);
      toast('success', t(detector ? 'dlpAdmin.keywordListSaved' : 'dlpAdmin.keywordListAdded', { name: form.name.trim() }));
      navigate('/admin/dlp/keywords');
    }
  };

  const termsError =
    shown && problems.terms
      ? t(`dlpAdmin.keywordProblem.${problems.terms}`, { max: MAX_TERMS, length: TERM_MAX, count: parsed.tooLong.length })
      : undefined;

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
          <h2 className="text-lg font-semibold text-gray-900">{detector ? t('dlpAdmin.editKeywordList') : t('dlpAdmin.addKeywordList')}</h2>
          <Link to="/admin/dlp/keywords" className="btn-secondary">
            <ArrowLeft className="mr-2 h-4 w-4" aria-hidden="true" />
            {t('dlpAdmin.backToKeywordLists')}
          </Link>
        </div>

        <Card>
          <div className="space-y-4">
            <Input
              id="keyword-list-name"
              label={t('common.name')}
              value={form.name}
              maxLength={DETECTOR_NAME_MAX}
              onChange={(event) => setForm((previous) => ({ ...previous, name: event.target.value }))}
              error={shown && problems.name ? t('dlpAdmin.keywordProblem.name') : undefined}
            />
            <div className="space-y-1.5">
              <label htmlFor="keyword-list-terms" className="block text-sm font-medium text-gray-700">
                {t('dlpAdmin.terms')}
              </label>
              <textarea
                id="keyword-list-terms"
                className="input-field min-h-[240px] resize-y font-mono"
                value={form.terms}
                spellCheck={false}
                aria-invalid={termsError ? true : undefined}
                aria-describedby={termsError ? 'keyword-list-terms-error keyword-list-terms-hint' : 'keyword-list-terms-hint'}
                onChange={(event) => setForm((previous) => ({ ...previous, terms: event.target.value }))}
              />
              {termsError && (
                <p id="keyword-list-terms-error" className="text-sm text-red-600">
                  {termsError}
                </p>
              )}
              <p id="keyword-list-terms-hint" className="text-sm text-gray-500">
                {t('dlpAdmin.termsHint', { max: MAX_TERMS, length: TERM_MAX })}
              </p>
              <p className="text-sm text-gray-700" aria-live="polite">
                {t('dlpAdmin.termCount', { count: parsed.terms.length })}
                {parsed.duplicates > 0 && ` ${t('dlpAdmin.duplicateTerms', { count: parsed.duplicates })}`}
              </p>
            </div>
          </div>
        </Card>

        {nothingChanged && shown && (
          <Alert variant="info" role="status">
            {t('dlpAdmin.nothingChanged')}
          </Alert>
        )}

        <Button type="submit" className="w-full">
          {detector ? t('common.save') : t('dlpAdmin.addKeywordList')}
        </Button>
      </form>

      <ConfirmChange
        open={confirming}
        title={detector ? t('dlpAdmin.confirmEditKeywordList') : t('dlpAdmin.confirmAddKeywordList')}
        lines={lines}
        action={detector ? t('common.save') : t('dlpAdmin.addKeywordList')}
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
