import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Check, Copy } from 'lucide-react';
import type { SsoDomain, SsoGroupRole, TenantSsoConnection, TenantSsoSettings } from '@/api';
import { PageShell } from '@/components/layout';
import {
  Alert,
  Badge,
  Button,
  Card,
  CardTitle,
  Dialog,
  Input,
  Select,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import { useUserEmails } from '@/hooks/admin';
import {
  claimSsoDomain,
  deleteSsoDomain,
  ssoKeys,
  updateTenantSso,
  useTenantSso,
  verifySsoDomain,
  withDomain,
  withoutDomain,
} from '@/hooks/sso';
import type { Role } from '@/hooks/users';
import { formatDate } from '@/lib/formatters';
import { errorMessage, isAccessProblem, problemCode } from '@/lib/problems';
import { AdminAccessNote } from './AdminAccessNote';
import {
  addGroupRole,
  changedSsoFields,
  claimDomain,
  domainState,
  formOf,
  MAX_GROUP_LENGTH,
  MAX_GROUP_ROLES,
  MAX_SSO_DOMAINS,
  removeGroupRole,
  setGroupRole,
  ssoRequiredBlockers,
  verifyProblem,
  type ClaimProblem,
  type DomainState,
  type GroupProblem,
  type SsoForm,
} from './ssoForm';

const ROLES: readonly Role[] = ['member', 'admin'];

const stateVariant: Record<DomainState, 'warning' | 'info' | 'success'> = {
  pending: 'warning',
  verified: 'info',
  linked: 'success',
};

/**
 * Single sign-on (#231; FR-26, authn-authz 2.5): the identity provider an operator connected, the email domains the
 * tenant proves with a DNS TXT record, and the sign-in rules: require SSO, the admin's confirmation that the identity
 * provider enforces MFA, members created at their first SSO sign-in, and the groups that choose their role. Every
 * change is a step-up operation: `apiClient` asks the admin to confirm it's them and sends it again (#232); a local
 * admin also needs a passkey sign-in (`AdminAccessNote`).
 */
export function SsoPage() {
  const { t } = useTranslation();
  const sso = useTenantSso();

  return (
    <PageShell title={t('sso.title')}>
      <div className="mx-auto max-w-3xl space-y-6">
        <p className="text-sm text-gray-600">{t('sso.intro')}</p>
        {sso.isPending ? (
          <div className="flex justify-center py-12">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : sso.isError ? (
          isAccessProblem(sso.error) ? <AdminAccessNote error={sso.error} /> : <Alert>{errorMessage(sso.error, t)}</Alert>
        ) : (
          <>
            <ConnectionCard connection={sso.data.connection} />
            <DomainsCard settings={sso.data} />
            <RulesForm settings={sso.data} />
          </>
        )}
      </div>
    </PageShell>
  );
}

function ConnectionCard({ connection }: { connection: TenantSsoConnection | null }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardTitle>{t('sso.connection.title')}</CardTitle>
      {connection === null ? (
        <p className="mt-2 text-sm text-gray-600">{t('sso.connection.none')}</p>
      ) : (
        <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-[auto_1fr]">
          <dt className="font-medium text-gray-700">{t('sso.connection.statusLabel')}</dt>
          <dd>
            <Badge variant={connection.status === 'active' ? 'success' : 'default'}>
              {t(`sso.connection.status.${connection.status}`)}
            </Badge>
          </dd>
          <dt className="font-medium text-gray-700">{t('sso.connection.kind')}</dt>
          <dd className="text-gray-900">{t(`sso.connection.kinds.${connection.kind}`)}</dd>
          <dt className="font-medium text-gray-700">{t('sso.connection.providerName')}</dt>
          <dd>
            <code className="text-xs break-all">{connection.provider_name}</code>
          </dd>
          {connection.issuer && (
            <>
              <dt className="font-medium text-gray-700">{t('sso.connection.issuer')}</dt>
              <dd className="break-all text-gray-900">{connection.issuer}</dd>
            </>
          )}
        </dl>
      )}
    </Card>
  );
}

/** Puts the settings the API answered with in the query cache, so every card shows them. */
function useSetSettings() {
  const queryClient = useQueryClient();
  return (update: (settings: TenantSsoSettings) => TenantSsoSettings) =>
    queryClient.setQueryData<TenantSsoSettings>(ssoKeys.settings, (current) => (current ? update(current) : current));
}

function DomainsCard({ settings }: { settings: TenantSsoSettings }) {
  const { t } = useTranslation();
  const setSettings = useSetSettings();
  const [input, setInput] = useState('');
  const [problem, setProblem] = useState<ClaimProblem | null>(null);
  const [claiming, setClaiming] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [removing, setRemoving] = useState<SsoDomain | null>(null);

  const claim = async () => {
    const checked = claimDomain(settings.domains, input);
    if ('problem' in checked) {
      setProblem(checked.problem);
      return;
    }
    setClaiming(true);
    setError(null);
    try {
      const domain = await claimSsoDomain(checked.domain);
      setSettings((current) => withDomain(current, domain));
      setInput('');
      toast('success', t('sso.domains.claimed', { domain: domain.domain }));
    } catch (failure) {
      setError(failure);
    } finally {
      setClaiming(false);
    }
  };

  return (
    <Card>
      <CardTitle>{t('sso.domains.title')}</CardTitle>
      <p className="mt-2 text-sm text-gray-600">{t('sso.domains.intro')}</p>

      {settings.domains.length === 0 ? (
        <p className="mt-4 text-sm text-gray-600">{t('sso.domains.empty')}</p>
      ) : (
        <ul className="mt-4 space-y-4">
          {settings.domains.map((domain) => (
            <DomainItem key={domain.id} domain={domain} onRemove={() => setRemoving(domain)} />
          ))}
        </ul>
      )}

      <form
        className="mt-6 space-y-3"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void claim();
        }}
      >
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
          <div className="flex-1">
            <Input
              id="sso-claim-domain"
              label={t('sso.domains.claimLabel')}
              placeholder={t('sso.domains.placeholder')}
              value={input}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setInput(event.target.value);
                setProblem(null);
              }}
              error={problem ? t(`sso.domains.problem.${problem}`, { max: MAX_SSO_DOMAINS }) : undefined}
              helperText={t('sso.domains.count', { count: settings.domains.length, max: MAX_SSO_DOMAINS })}
            />
          </div>
          <Button type="submit" loading={claiming} className="sm:mt-7">
            {t('sso.domains.claim')}
          </Button>
        </div>
        {error !== null && <ProblemNote error={error} />}
      </form>

      <RemoveDomainDialog
        domain={removing}
        onClose={() => setRemoving(null)}
        onRemoved={(domain) => {
          setSettings((current) => withoutDomain(current, domain.id));
          setRemoving(null);
          toast('success', t('sso.domains.removed', { domain: domain.domain }));
        }}
      />
    </Card>
  );
}

function DomainItem({ domain, onRemove }: { domain: SsoDomain; onRemove: () => void }) {
  const { t, i18n } = useTranslation();
  const setSettings = useSetSettings();
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const state = domainState(domain);

  const verify = async () => {
    setVerifying(true);
    setError(null);
    try {
      const proven = await verifySsoDomain(domain.id);
      setSettings((current) => withDomain(current, proven));
      toast('success', t('sso.domains.verified', { domain: proven.domain }));
    } catch (failure) {
      setError(failure);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <li className="rounded-lg p-4 ring-1 ring-gray-200">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-medium text-gray-900 break-all">{domain.domain}</span>
          <Badge variant={stateVariant[state]}>{t(`sso.domains.status.${state}`)}</Badge>
        </div>
        <div className="flex gap-2">
          {state === 'pending' && (
            <Button
              type="button"
              size="sm"
              onClick={() => void verify()}
              loading={verifying}
              aria-label={t('sso.domains.verifyDomain', { domain: domain.domain })}
            >
              {t('sso.domains.verify')}
            </Button>
          )}
          <Button
            type="button"
            size="sm"
            variant="secondary"
            onClick={onRemove}
            aria-label={t('sso.domains.removeDomain', { domain: domain.domain })}
          >
            {t('sso.domains.remove')}
          </Button>
        </div>
      </div>
      <p className="mt-2 text-sm text-gray-600">
        {t(`sso.domains.statusHint.${state}`)}
        {domain.verified_at && ` ${t('sso.domains.verifiedOn', { date: formatDate(domain.verified_at, i18n.language) })}`}
      </p>
      {state === 'pending' && (
        <div className="mt-3 space-y-2">
          <p className="text-sm text-gray-700">{t('sso.domains.publish')}</p>
          <CopyField
            label={t('sso.domains.txtName')}
            value={domain.txt_record_name}
            copyLabel={t('sso.domains.copyName', { domain: domain.domain })}
          />
          <CopyField
            label={t('sso.domains.txtValue')}
            value={domain.txt_record_value}
            copyLabel={t('sso.domains.copyValue', { domain: domain.domain })}
          />
        </div>
      )}
      {error !== null && (
        <div className="mt-3">
          <VerifyNote error={error} />
        </div>
      )}
    </li>
  );
}

/** A value to publish, shown in full and selectable, with a button that copies it. */
function CopyField({ label, value, copyLabel }: { label: string; value: string; copyLabel: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      toast('error', t('sso.domains.copyFailed'));
    }
  };

  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
      <span className="w-40 shrink-0 text-xs font-medium text-gray-700">{label}</span>
      <code className="flex-1 rounded bg-gray-50 px-2 py-1 text-xs break-all text-gray-900 select-all">{value}</code>
      <Button type="button" size="sm" variant="ghost" onClick={() => void copy()} aria-label={copyLabel}>
        {copied ? <Check className="mr-1 h-4 w-4" aria-hidden="true" /> : <Copy className="mr-1 h-4 w-4" aria-hidden="true" />}
        {copied ? t('apiKeys.copied') : t('apiKeys.copy')}
      </Button>
    </div>
  );
}

function RemoveDomainDialog({
  domain,
  onClose,
  onRemoved,
}: {
  domain: SsoDomain | null;
  onClose: () => void;
  onRemoved: (domain: SsoDomain) => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const close = () => {
    setError(null);
    onClose();
  };

  const remove = async () => {
    if (!domain) return;
    setBusy(true);
    setError(null);
    try {
      await deleteSsoDomain(domain.id);
      onRemoved(domain);
    } catch (failure) {
      if (problemCode(failure) === 'not_found') {
        onRemoved(domain); // already gone
      } else {
        setError(failure);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={domain !== null} onClose={close} title={t('sso.domains.removeTitle')}>
      <p className="text-sm text-gray-700">{t('sso.domains.removeBody', { domain: domain?.domain ?? '' })}</p>
      {error !== null && (
        <div className="mt-4">
          <ProblemNote error={error} />
        </div>
      )}
      <div className="mt-6 flex justify-end gap-3">
        <Button type="button" variant="secondary" onClick={close} disabled={busy}>
          {t('common.cancel')}
        </Button>
        <Button type="button" variant="danger" onClick={() => void remove()} loading={busy}>
          {t('sso.domains.remove')}
        </Button>
      </div>
    </Dialog>
  );
}

function RulesForm({ settings }: { settings: TenantSsoSettings }) {
  const { t, i18n } = useTranslation();
  const setSettings = useSetSettings();
  const [form, setForm] = useState<SsoForm>(() => formOf(settings));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [mfaChecked, setMfaChecked] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [mfaError, setMfaError] = useState<unknown>(null);
  const emails = useUserEmails(Boolean(settings.sso_mfa_confirmed_by));

  const body = changedSsoFields(settings, form);
  const changed = body !== null && Object.keys(body).length > 0;
  const blockers = ssoRequiredBlockers(settings);
  // Turning it off is always possible; turning it on needs both.
  const requiredBlocked = !settings.sso_required && blockers.length > 0;

  const save = async () => {
    if (!body || !changed) return;
    setSaving(true);
    setError(null);
    try {
      const saved = await updateTenantSso(body);
      setSettings(() => saved);
      setForm(formOf(saved));
      toast('success', t('sso.rules.saved'));
    } catch (failure) {
      setError(failure);
    } finally {
      setSaving(false);
    }
  };

  const confirmMfa = async () => {
    setConfirming(true);
    setMfaError(null);
    try {
      const saved = await updateTenantSso({ confirm_idp_mfa: true });
      setSettings(() => saved);
      setMfaChecked(false);
      toast('success', t('sso.rules.mfaDone'));
    } catch (failure) {
      setMfaError(failure);
    } finally {
      setConfirming(false);
    }
  };

  const who = settings.sso_mfa_confirmed_by
    ? (emails.data?.get(settings.sso_mfa_confirmed_by) ?? settings.sso_mfa_confirmed_by)
    : null;

  return (
    <>
      <Card>
        <CardTitle>{t('sso.rules.mfaTitle')}</CardTitle>
        <p className="mt-2 text-sm text-gray-600">{t('sso.rules.mfaIntro')}</p>
        <p className="mt-3 text-sm font-medium text-gray-900" role="status">
          {who && settings.sso_mfa_confirmed_at
            ? t('sso.rules.mfaConfirmed', { who, date: formatDate(settings.sso_mfa_confirmed_at, i18n.language) })
            : t('sso.rules.mfaNotConfirmed')}
        </p>
        <form
          className="mt-4 space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (mfaChecked) void confirmMfa();
          }}
        >
          <label className="flex items-start gap-3">
            <input
              type="checkbox"
              checked={mfaChecked}
              onChange={(event) => setMfaChecked(event.target.checked)}
              className="mt-1 h-4 w-4 accent-brand-600"
            />
            <span className="text-sm text-gray-900">{t('sso.rules.mfaCheck')}</span>
          </label>
          {mfaError !== null && <ProblemNote error={mfaError} />}
          <Button type="submit" variant="secondary" loading={confirming} disabled={!mfaChecked}>
            {t(settings.sso_mfa_confirmed_at ? 'sso.rules.mfaConfirmAgain' : 'sso.rules.mfaConfirm')}
          </Button>
        </form>
      </Card>

      <form
        className="space-y-6"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <Card>
          <CardTitle>{t('sso.rules.title')}</CardTitle>
          <div className="mt-4 space-y-5">
            <div>
              <label className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={form.sso_required}
                  disabled={requiredBlocked}
                  onChange={(event) => setForm((previous) => ({ ...previous, sso_required: event.target.checked }))}
                  aria-describedby="sso-required-hint"
                  className="mt-1 h-4 w-4 accent-brand-600"
                />
                <span>
                  <span className="block text-sm font-medium text-gray-900">{t('sso.rules.required')}</span>
                  <span id="sso-required-hint" className="block text-sm text-gray-600">
                    {t('sso.rules.requiredHint')}
                  </span>
                </span>
              </label>
              {requiredBlocked && (
                <div className="mt-2 ml-7 text-sm text-gray-700">
                  <p>{t('sso.rules.requiredBlocked')}</p>
                  <ul className="mt-1 list-disc pl-5">
                    {blockers.map((blocker) => (
                      <li key={blocker}>{t(`sso.rules.blocker.${blocker}`)}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            <label className="flex items-start gap-3">
              <input
                type="checkbox"
                checked={form.jit_provisioning}
                onChange={(event) => setForm((previous) => ({ ...previous, jit_provisioning: event.target.checked }))}
                aria-describedby="sso-jit-hint"
                className="mt-1 h-4 w-4 accent-brand-600"
              />
              <span>
                <span className="block text-sm font-medium text-gray-900">{t('sso.rules.jit')}</span>
                <span id="sso-jit-hint" className="block text-sm text-gray-600">
                  {t('sso.rules.jitHint')}
                </span>
              </span>
            </label>
          </div>
        </Card>

        <GroupRolesCard
          list={form.group_roles}
          onChange={(group_roles) => setForm((previous) => ({ ...previous, group_roles }))}
        />

        {error !== null &&
          (problemCode(error) === 'validation_failed' ? (
            <Alert>{t('sso.rules.invalid')}</Alert>
          ) : (
            <ProblemNote error={error} />
          ))}

        <Button type="submit" loading={saving} disabled={!changed} className="w-full">
          {t('common.save')}
        </Button>
      </form>
    </>
  );
}

function GroupRolesCard({ list, onChange }: { list: SsoGroupRole[]; onChange: (list: SsoGroupRole[]) => void }) {
  const { t } = useTranslation();
  const [group, setGroup] = useState('');
  const [role, setRole] = useState<Role>('member');
  const [problem, setProblem] = useState<GroupProblem | null>(null);
  const roleLabel = (value: Role) => t(value === 'admin' ? 'admin.roleAdmin' : 'admin.roleMember');

  const add = () => {
    const result = addGroupRole(list, group, role);
    if ('problem' in result) {
      setProblem(result.problem);
      return;
    }
    onChange(result.list);
    setGroup('');
    setRole('member');
  };

  return (
    <Card>
      <CardTitle>{t('sso.groups.title')}</CardTitle>
      <p className="mt-2 text-sm text-gray-600">{t('sso.groups.intro')}</p>
      {list.length === 0 ? (
        <p className="mt-4 text-sm text-gray-600">{t('sso.groups.empty')}</p>
      ) : (
        <div className="mt-4">
          <Table label={t('sso.groups.title')} caption={t('sso.groups.caption')}>
            <TableHead>
              <tr>
                <TableHeader>{t('sso.groups.group')}</TableHeader>
                <TableHeader>{t('sso.groups.role')}</TableHeader>
                <TableHeader>
                  <span className="sr-only">{t('common.actions')}</span>
                </TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {list.map((entry) => (
                <TableRow key={entry.group}>
                  <TableCell>
                    <span className="break-all text-gray-900">{entry.group}</span>
                  </TableCell>
                  <TableCell>
                    <Select
                      label={t('sso.groups.roleFor', { group: entry.group })}
                      hideLabel
                      className="py-1"
                      value={entry.role}
                      onChange={(event) => onChange(setGroupRole(list, entry.group, event.target.value as Role))}
                      options={ROLES.map((value) => ({ value, label: roleLabel(value) }))}
                    />
                  </TableCell>
                  <TableCell>
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      onClick={() => onChange(removeGroupRole(list, entry.group))}
                      aria-label={t('sso.groups.remove', { group: entry.group })}
                    >
                      {t('common.remove')}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-[1fr_12rem_auto] sm:items-start">
        <Input
          id="sso-group-name"
          label={t('sso.groups.groupLabel')}
          value={group}
          maxLength={MAX_GROUP_LENGTH}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => {
            setGroup(event.target.value);
            setProblem(null);
          }}
          onKeyDown={(event) => {
            // Enter adds the mapping; it never submits the whole form.
            if (event.key === 'Enter') {
              event.preventDefault();
              add();
            }
          }}
          error={problem ? t(`sso.groups.problem.${problem}`, { max: problem === 'tooLong' ? MAX_GROUP_LENGTH : MAX_GROUP_ROLES }) : undefined}
          helperText={t('sso.groups.count', { count: list.length, max: MAX_GROUP_ROLES })}
        />
        <Select
          label={t('sso.groups.roleLabel')}
          value={role}
          onChange={(event) => setRole(event.target.value as Role)}
          options={ROLES.map((value) => ({ value, label: roleLabel(value) }))}
        />
        <Button type="button" variant="secondary" onClick={add} className="sm:mt-7">
          {t('sso.groups.add')}
        </Button>
      </div>
      <p className="mt-3 text-sm text-gray-600">{t('sso.groups.saveNote')}</p>
    </Card>
  );
}

/** A failed call: the stronger-sign-in note for a passkey or a cancelled step-up, else the problem's text. */
function ProblemNote({ error }: { error: unknown }) {
  const { t } = useTranslation();
  return isAccessProblem(error) ? <AdminAccessNote error={error} /> : <Alert>{errorMessage(error, t)}</Alert>;
}

/** A failed verify: a missing TXT record and a domain proven elsewhere have their own explanation. */
function VerifyNote({ error }: { error: unknown }) {
  const { t } = useTranslation();
  const problem = verifyProblem(problemCode(error));
  return problem ? <Alert>{t(`sso.domains.verifyProblem.${problem}`)}</Alert> : <ProblemNote error={error} />;
}
