import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { PageShell } from '@/components/layout';
import { Alert, Button, Card, CardTitle, Input, Select, Spinner, toast } from '@/components/ui';
import { queryKeys, useTenantPolicy } from '@/hooks/transfers';
import { updateTenantPolicy, type TenantPolicy } from '@/hooks/users';
import { EXPIRY_CHOICES, normalizeDuration } from '@/lib/durations';
import { formatDate } from '@/lib/formatters';
import { errorMessage, failureOf, isAccessProblem } from '@/lib/problems';
import { useDurationLabel } from '@/lib/useDurationLabel';
import { AdminAccessNote } from './AdminAccessNote';
import { DomainListEditor } from './DomainListEditor';
import { overlapping } from './domains';
import {
  changedFields,
  formOf,
  MAX_RETENTION_DAYS,
  MIN_RETENTION_DAYS,
  policyFieldErrors,
  retentionDays,
  type PolicyField,
  type PolicyForm,
} from './policyForm';
import { SuppressionClearForm } from './SuppressionClearForm';

/**
 * The tenant policy (#197; FR-3, FR-13, FR-18, FR-23, FR-33), on the contract's fields: the longest expiry, what
 * happens to files that can't be scanned, how long received files are kept, and the default language of recipients'
 * emails and pages; and the allowed and blocked recipient domains (#217, FR-24). Saving sends only what changed. Below
 * the policy, a form clears a suppressed email address (#217, FR-7).
 */
export function TenantPolicyPage() {
  const { t } = useTranslation();
  const policy = useTenantPolicy();

  return (
    <PageShell title={t('admin.tenantPolicy')}>
      <div className="mx-auto max-w-2xl space-y-6">
        {policy.isPending ? (
          <div className="flex justify-center py-12">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : policy.isError ? (
          <Alert>{errorMessage(policy.error, t)}</Alert>
        ) : (
          <PolicyEditor policy={policy.data} />
        )}
        <SuppressionClearForm />
      </div>
    </PageShell>
  );
}

function PolicyEditor({ policy }: { policy: TenantPolicy }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const durationLabel = useDurationLabel();
  const [form, setForm] = useState<PolicyForm>(() => formOf(policy));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [fields, setFields] = useState<Partial<Record<PolicyField, string>>>({});

  // A newer policy from the server (after a save) becomes the form's starting point.
  useEffect(() => setForm(formOf(policy)), [policy]);

  const expiryChoices = useMemo(() => {
    const current = normalizeDuration(policy.max_expiry);
    const choices: string[] = [...EXPIRY_CHOICES];
    if (current && !choices.includes(current)) choices.push(current);
    return choices;
  }, [policy.max_expiry]);

  const body = changedFields(policy, form);
  const retentionInvalid = retentionDays(form.received_file_retention_days) === null;
  const set = <K extends keyof PolicyForm>(key: K, value: PolicyForm[K]) => {
    setForm((previous) => ({ ...previous, [key]: value }));
    setFields((previous) => ({ ...previous, [key]: undefined }));
  };

  const save = async () => {
    if (!body || Object.keys(body).length === 0) return;
    setSaving(true);
    setError(null);
    setFields({});
    try {
      const saved = await updateTenantPolicy(body);
      queryClient.setQueryData(queryKeys.tenantPolicy, saved);
      toast('success', t('admin.policyUpdated'));
    } catch (failure) {
      setFields(policyFieldErrors(failureOf(failure)).fields);
      setError(failure);
    } finally {
      setSaving(false);
    }
  };

  const fieldError = (field: PolicyField) => (fields[field] ? t(`admin.policyInvalid.${field}`) : undefined);

  return (
    <form
      className="space-y-6"
      onSubmit={(event) => {
        event.preventDefault();
        void save();
      }}
    >
      <p className="text-sm text-gray-500">{t('admin.policyUpdatedAt', { date: formatDate(policy.updated_at, i18n.language) })}</p>

      <Card>
        <CardTitle>{t('admin.transferSettings')}</CardTitle>
        <div className="mt-4 space-y-4">
          <Select
            label={t('admin.maxExpiry')}
            value={form.max_expiry}
            onChange={(event) => set('max_expiry', event.target.value)}
            options={expiryChoices.map((value) => ({ value, label: durationLabel(value) }))}
            hint={t('admin.maxExpiryHint')}
            error={fieldError('max_expiry')}
          />
          <Select
            label={t('admin.defaultLocale')}
            value={form.default_locale}
            onChange={(event) => set('default_locale', event.target.value as PolicyForm['default_locale'])}
            options={(['en', 'ja'] as const).map((value) => ({ value, label: t(`locales.${value}`) }))}
            hint={t('admin.defaultLocaleHint')}
            error={fieldError('default_locale')}
          />
        </div>
      </Card>

      <Card>
        <CardTitle>{t('admin.security')}</CardTitle>
        <fieldset className="mt-4" aria-describedby={fields.unscannable_policy ? 'unscannable-error' : undefined}>
          <legend className="text-sm font-medium text-gray-700">{t('admin.unscannablePolicy')}</legend>
          <div className="mt-3 space-y-3">
            {(['block', 'allow_with_warning'] as const).map((value) => (
              <label key={value} className="flex items-start gap-3">
                <input
                  type="radio"
                  name="unscannable_policy"
                  value={value}
                  checked={form.unscannable_policy === value}
                  onChange={() => set('unscannable_policy', value)}
                  className="mt-1 h-4 w-4 accent-brand-600"
                />
                <span>
                  <span className="block text-sm font-medium text-gray-900">{t(`admin.unscannable.${value}`)}</span>
                  <span className="block text-sm text-gray-600">{t(`admin.unscannableHint.${value}`)}</span>
                </span>
              </label>
            ))}
          </div>
          {fields.unscannable_policy && (
            <p id="unscannable-error" className="mt-2 text-sm text-red-600">
              {fieldError('unscannable_policy')}
            </p>
          )}
        </fieldset>
      </Card>

      <Card>
        <CardTitle>{t('domains.title')}</CardTitle>
        <p className="mt-2 text-sm text-gray-600">{t('domains.intro')}</p>
        <div className="mt-4 space-y-6">
          <DomainListEditor
            label={t('domains.allowed')}
            hint={t('domains.allowedHint')}
            domains={form.allowed_domains}
            onChange={(domains) => set('allowed_domains', domains)}
            error={fieldError('allowed_domains')}
          />
          <DomainListEditor
            label={t('domains.blocked')}
            hint={t('domains.blockedHint')}
            domains={form.blocked_domains}
            onChange={(domains) => set('blocked_domains', domains)}
            error={fieldError('blocked_domains')}
          />
          {overlapping(form.allowed_domains, form.blocked_domains).length > 0 && (
            <Alert variant="warning" role="status">
              {t('domains.overlap', { domains: overlapping(form.allowed_domains, form.blocked_domains).join(', ') })}
            </Alert>
          )}
        </div>
      </Card>

      <Card>
        <CardTitle>{t('admin.receivedFiles')}</CardTitle>
        <div className="mt-4">
          <Input
            id="retention-days"
            label={t('admin.retentionPeriod')}
            inputMode="numeric"
            value={form.received_file_retention_days}
            onChange={(event) => set('received_file_retention_days', event.target.value)}
            helperText={t('admin.retentionHint', { min: MIN_RETENTION_DAYS, max: MAX_RETENTION_DAYS })}
            error={
              retentionInvalid
                ? t('admin.retentionInvalid', { min: MIN_RETENTION_DAYS, max: MAX_RETENTION_DAYS })
                : fieldError('received_file_retention_days')
            }
          />
        </div>
      </Card>

      {error !== null && (isAccessProblem(error) ? <AdminAccessNote error={error} /> : <Alert>{errorMessage(error, t)}</Alert>)}

      <Button type="submit" loading={saving} disabled={!body || Object.keys(body).length === 0} className="w-full">
        {t('common.save')}
      </Button>
    </form>
  );
}
