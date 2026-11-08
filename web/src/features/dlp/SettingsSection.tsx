import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { X } from 'lucide-react';
import { Alert, Badge, Button, Card, CardTitle, Input, Select, toast } from '@/components/ui';
import type { DlpPolicy } from '@/api';
import { dlpKeys, invalidateDlp, updateDlpPolicy, useDlpPolicy } from '@/hooks/dlp';
import { formatDate } from '@/lib/formatters';
import { useDurationLabel } from '@/lib/useDurationLabel';
import { ConfirmChange } from './ConfirmChange';
import { LoadError, Loading } from './DlpAdminPage';
import {
  addDomains,
  approvalTimeoutOptions,
  domainChanges,
  MAX_TRUSTED_DOMAINS,
  MODES,
  settingsFormOf,
  settingsUpdate,
  type SettingsForm,
} from './dlpForms';
import { useWrite } from './useWrite';

/** How many domains a confirmation names before "and N more". */
const NAMED_DOMAINS = 10;

/**
 * The policy's settings (#218, #221; FR-43, FR-45, FR-52): the mode (enforce, or monitor, which records every decision
 * and holds, warns and blocks nothing, with a warning that says so), the trusted domains, the approval timeout, and
 * how many active approvers the tenant has.
 */
export function SettingsSection() {
  const policy = useDlpPolicy();
  if (policy.isPending) return <Loading />;
  if (policy.isError) return <LoadError error={policy.error} />;
  // Keyed by version: a saved or reloaded policy starts the form over from it.
  return <SettingsEditor key={policy.data.version} policy={policy.data} />;
}

function SettingsEditor({ policy }: { policy: DlpPolicy }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const durationLabel = useDurationLabel();
  const [form, setForm] = useState<SettingsForm>(() => settingsFormOf(policy));
  const [domainInput, setDomainInput] = useState('');
  const [domainError, setDomainError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const write = useWrite();

  const body = settingsUpdate(policy, form);
  const timeoutOptions = useMemo(() => approvalTimeoutOptions(policy.approval_timeout), [policy.approval_timeout]);

  const add = () => {
    const result = addDomains(form.trusted_domains, domainInput);
    setForm((previous) => ({ ...previous, trusted_domains: result.domains }));
    if (result.invalid.length > 0) {
      setDomainError(t('dlpAdmin.domainInvalid', { value: result.invalid.join(t('common.listSeparator')) }));
      setDomainInput(result.invalid.join(' '));
    } else if (result.overLimit.length > 0) {
      setDomainError(t('dlpAdmin.domainLimit', { max: MAX_TRUSTED_DOMAINS }));
      setDomainInput('');
    } else {
      setDomainError(null);
      setDomainInput('');
    }
  };

  const remove = (domain: string) =>
    setForm((previous) => ({ ...previous, trusted_domains: previous.trusted_domains.filter((item) => item !== domain) }));

  const lines = useMemo(() => {
    const out: string[] = [];
    if (body?.mode) {
      out.push(t('dlpAdmin.change.mode', { from: t(`dlpAdmin.modes.${policy.mode}`), to: t(`dlpAdmin.modes.${body.mode}`) }));
      out.push(t(`dlpAdmin.change.modeEffect.${body.mode}`));
    }
    const { added, removed } = domainChanges(policy.trusted_domains, form.trusted_domains);
    const named = (domains: string[]) => {
      const shown = domains.slice(0, NAMED_DOMAINS).join(t('common.listSeparator'));
      return domains.length > NAMED_DOMAINS ? `${shown} ${t('dlpAdmin.andMore', { count: domains.length - NAMED_DOMAINS })}` : shown;
    };
    if (added.length > 0) out.push(t('dlpAdmin.change.trust', { domains: named(added) }));
    if (removed.length > 0) out.push(t('dlpAdmin.change.untrust', { domains: named(removed) }));
    if (body?.approval_timeout) {
      out.push(
        t('dlpAdmin.change.timeout', { from: durationLabel(policy.approval_timeout), to: durationLabel(form.approval_timeout) }),
      );
    }
    return out;
  }, [policy, form, body, t, durationLabel]);

  const save = async () => {
    if (!body) return;
    const ok = await write.run(async () => {
      const saved = await updateDlpPolicy(body);
      queryClient.setQueryData(dlpKeys.policy, saved);
    });
    if (ok) {
      setConfirming(false);
      toast('success', t('dlpAdmin.settingsSaved'));
    }
  };

  const reload = () => {
    setConfirming(false);
    write.reset();
    void invalidateDlp(queryClient);
  };

  return (
    <>
      <form
        className="mx-auto max-w-2xl space-y-6"
        onSubmit={(event) => {
          event.preventDefault();
          if (body) {
            write.reset();
            setConfirming(true);
          }
        }}
      >
        <p className="text-sm text-gray-500">
          {t('dlpAdmin.version', { version: policy.version, date: formatDate(policy.updated_at, i18n.language) })}
        </p>

        <Card>
          <fieldset aria-describedby={form.mode === 'monitor' ? 'dlp-monitor-warning' : undefined}>
            <legend className="flex flex-wrap items-center gap-2 text-lg font-semibold text-gray-900">
              {t('dlpAdmin.mode')}
              <Badge variant={policy.mode === 'enforce' ? 'success' : 'warning'}>
                {t('dlpAdmin.currentMode', { mode: t(`dlpAdmin.modes.${policy.mode}`) })}
              </Badge>
            </legend>
            <div className="mt-3 space-y-3">
              {MODES.map((value) => (
                <label key={value} className="flex items-start gap-3">
                  <input
                    type="radio"
                    name="dlp-mode"
                    value={value}
                    checked={form.mode === value}
                    onChange={() => setForm((previous) => ({ ...previous, mode: value }))}
                    className="mt-1 h-4 w-4 accent-brand-600"
                  />
                  <span>
                    <span className="block text-sm font-medium text-gray-900">{t(`dlpAdmin.modes.${value}`)}</span>
                    <span className="block text-sm text-gray-600">{t(`dlpAdmin.modeHint.${value}`)}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
          {form.mode === 'monitor' && (
            <Alert variant="warning" role="status" className="mt-4">
              <p id="dlp-monitor-warning">{t('dlpAdmin.monitorWarning')}</p>
            </Alert>
          )}
        </Card>

        <Card>
          <CardTitle>{t('dlpAdmin.trustedDomains')}</CardTitle>
          <p className="mt-2 text-sm text-gray-600">{t('dlpAdmin.trustedDomainsHint')}</p>
          <div className="mt-4 flex flex-wrap items-start gap-3">
            <div className="min-w-0 flex-1">
              <Input
                id="trusted-domain"
                label={t('dlpAdmin.addDomain')}
                value={domainInput}
                placeholder="partner.example"
                autoComplete="off"
                onChange={(event) => setDomainInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    event.preventDefault();
                    if (domainInput.trim()) add();
                  }
                }}
                error={domainError ?? undefined}
                helperText={t('dlpAdmin.addDomainHint')}
              />
            </div>
            <Button type="button" variant="secondary" className="mt-7" disabled={!domainInput.trim()} onClick={add}>
              {t('dlpAdmin.add')}
            </Button>
          </div>
          <p className="mt-4 text-sm text-gray-500" aria-live="polite">
            {t('dlpAdmin.domainCount', { count: form.trusted_domains.length, max: MAX_TRUSTED_DOMAINS })}
          </p>
          {form.trusted_domains.length === 0 ? (
            <p className="mt-2 text-sm text-gray-600">{t('dlpAdmin.noTrustedDomains')}</p>
          ) : (
            <ul className="mt-2 flex flex-wrap gap-2" aria-label={t('dlpAdmin.trustedDomains')}>
              {form.trusted_domains.map((domain) => (
                <li key={domain} className="inline-flex items-center gap-1 rounded-full bg-gray-100 py-1 pl-3 pr-1 text-sm text-gray-800">
                  <span className="break-all">{domain}</span>
                  <button
                    type="button"
                    className="rounded-full p-1 text-gray-600 hover:bg-gray-200 hover:text-gray-900"
                    aria-label={t('dlpAdmin.removeDomain', { domain })}
                    onClick={() => remove(domain)}
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardTitle>{t('dlpAdmin.approvals')}</CardTitle>
          <div className="mt-4 space-y-4">
            <Select
              label={t('dlpAdmin.approvalTimeout')}
              value={form.approval_timeout}
              onChange={(event) => setForm((previous) => ({ ...previous, approval_timeout: event.target.value }))}
              options={timeoutOptions.map((value) => ({ value, label: durationLabel(value) }))}
              hint={t('dlpAdmin.approvalTimeoutHint')}
            />
            <p className="text-sm text-gray-700">
              {t('dlpAdmin.activeApprovers', { count: policy.active_approvers })}{' '}
              <Link to="/admin/users" className="font-semibold text-brand-700 underline hover:text-brand-800">
                {t('dlpAdmin.manageApprovers')}
              </Link>
            </p>
            {policy.active_approvers < 2 && (
              <Alert variant="info" role="status">
                {t('dlpAdmin.approversNeeded')}
              </Alert>
            )}
          </div>
        </Card>

        <Button type="submit" disabled={!body} className="w-full">
          {t('common.save')}
        </Button>
      </form>

      <ConfirmChange
        open={confirming}
        title={t('dlpAdmin.confirmSettings')}
        lines={lines}
        action={body?.mode === 'monitor' ? t('dlpAdmin.switchToMonitor') : t('common.save')}
        danger={body?.mode === 'monitor'}
        busy={write.busy}
        error={write.error}
        onConfirm={() => void save()}
        onClose={() => setConfirming(false)}
        onReload={reload}
      />
    </>
  );
}
