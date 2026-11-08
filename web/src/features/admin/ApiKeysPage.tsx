import { useReducer, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Check, Copy, Key, Plus } from 'lucide-react';
import { PageShell } from '@/components/layout';
import {
  Alert,
  Badge,
  Button,
  Card,
  Dialog,
  EmptyState,
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
import type { ApiKey } from '@/api';
import { adminKeys, createApiKey, revokeApiKey, useApiKeyList, useUserEmails } from '@/hooks/admin';
import { formatDate } from '@/lib/formatters';
import { errorMessage, failureOf, fieldErrors, isAccessProblem } from '@/lib/problems';
import { AdminAccessNote } from './AdminAccessNote';
import {
  API_KEY_SCOPES,
  createBody,
  EMPTY_KEY_FORM,
  KEY_DAY_CHOICES,
  keyFormProblems,
  keyStatus,
  mayClose,
  MAX_KEY_NAME,
  secretStep,
  toggleScope,
  type KeyForm,
  type KeyStatus,
} from './apiKeys';
import { ownerLabel } from '@/features/sender/owners';

const statusVariant: Record<KeyStatus, 'success' | 'default' | 'danger'> = {
  active: 'success',
  expired: 'default',
  revoked: 'danger',
};

/**
 * The tenant's API keys (#215; FR-32, authn-authz 5): the list with each key's prefix, scopes, owner, expiry and last
 * use; a create dialog that shows the secret once; and revocation, which any admin may do without a passkey. Creating
 * needs a recent sign-in and, for a local admin, a passkey (`AdminAccessNote` explains both).
 */
export function ApiKeysPage() {
  const { t, i18n } = useTranslation();
  const list = useApiKeyList();
  const keys = list.data?.pages.flatMap((page) => page.items) ?? [];
  const owners = useUserEmails(keys.length > 0);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const now = new Date();

  return (
    <PageShell
      title={t('admin.apiKeys')}
      actions={
        <Button onClick={() => setCreating(true)}>
          <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('admin.createApiKey')}
        </Button>
      }
    >
      <p className="text-sm text-gray-600">{t('apiKeys.intro')}</p>
      <Card padding={false}>
        {list.isPending ? (
          <div className="flex justify-center py-12">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : list.isError ? (
          <div className="p-4">
            {isAccessProblem(list.error) ? <AdminAccessNote error={list.error} /> : <Alert>{errorMessage(list.error, t)}</Alert>}
          </div>
        ) : keys.length === 0 ? (
          <EmptyState
            icon={Key}
            title={t('admin.noApiKeys')}
            description={t('admin.noApiKeysHint')}
            action={<Button onClick={() => setCreating(true)}>{t('admin.createApiKey')}</Button>}
          />
        ) : (
          <Table label={t('admin.apiKeys')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.name')}</TableHeader>
                <TableHeader>{t('admin.keyPrefix')}</TableHeader>
                <TableHeader>{t('admin.scopes')}</TableHeader>
                <TableHeader>{t('apiKeys.createdBy')}</TableHeader>
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>{t('common.expiresAt')}</TableHeader>
                <TableHeader>{t('admin.lastUsed')}</TableHeader>
                <TableHeader>
                  <span className="sr-only">{t('common.actions')}</span>
                </TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {keys.map((key) => {
                const status = keyStatus(key, now);
                return (
                  <TableRow key={key.id}>
                    <TableCell>
                      <span className="font-medium text-gray-900">{key.name}</span>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs">{key.key_prefix}…</code>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {key.scopes.map((scope) => (
                          <Badge key={scope} variant="info">
                            {scope}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>{ownerLabel(owners.data, key.created_by)}</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant[status]}>{t(`apiKeys.status.${status}`)}</Badge>
                    </TableCell>
                    <TableCell>{formatDate(key.expires_at, i18n.language)}</TableCell>
                    <TableCell>{key.last_used_at ? formatDate(key.last_used_at, i18n.language) : t('apiKeys.neverUsed')}</TableCell>
                    <TableCell>
                      {status !== 'revoked' && (
                        <Button
                          size="sm"
                          variant="danger"
                          aria-label={t('apiKeys.revokeKey', { name: key.name })}
                          onClick={() => setRevoking(key)}
                        >
                          {t('apiKeys.revoke')}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>
      {list.hasNextPage && (
        <div className="flex justify-center">
          <Button variant="secondary" onClick={() => void list.fetchNextPage()} loading={list.isFetchingNextPage}>
            {t('common.loadMore')}
          </Button>
        </div>
      )}

      <CreateKeyDialog open={creating} onClose={() => setCreating(false)} />
      <RevokeKeyDialog apiKey={revoking} onClose={() => setRevoking(null)} />
    </PageShell>
  );
}

function CreateKeyDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<KeyForm>(EMPTY_KEY_FORM);
  const [step, dispatch] = useReducer(secretStep, { step: 'form' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [touched, setTouched] = useState(false);
  const [copied, setCopied] = useState(false);
  const problems = keyFormProblems(form);

  const close = () => {
    if (!mayClose(step)) return;
    setForm(EMPTY_KEY_FORM);
    setError(null);
    setTouched(false);
    setCopied(false);
    dispatch({ type: 'reset' }); // the secret leaves memory with the dialog
    onClose();
  };

  const submit = async () => {
    setTouched(true);
    if (problems.length > 0) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createApiKey(createBody(form));
      const { secret, ...key } = created;
      dispatch({ type: 'created', key, secret });
      await queryClient.invalidateQueries({ queryKey: adminKeys.apiKeys });
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (step.step !== 'created') return;
    try {
      await navigator.clipboard.writeText(step.secret);
      setCopied(true);
    } catch {
      toast('error', t('apiKeys.copyFailed'));
    }
  };

  const serverFields = error !== null ? fieldErrors(failureOf(error)) : {};
  const nameError =
    (touched && problems.includes('name') ? t('apiKeys.nameInvalid', { max: MAX_KEY_NAME }) : undefined) ??
    (serverFields.name ? t('apiKeys.nameInvalid', { max: MAX_KEY_NAME }) : undefined);

  if (step.step === 'created') {
    return (
      <Dialog key="secret" open={open} onClose={close} title={t('apiKeys.createdTitle')}>
        <div className="space-y-4">
          <Alert variant="warning" role="status">
            {t('apiKeys.secretOnce')}
          </Alert>
          <div>
            <label htmlFor="api-key-secret" className="block text-sm font-medium text-gray-700">
              {t('apiKeys.secretLabel', { name: step.key.name })}
            </label>
            <div className="mt-1.5 flex gap-2">
              <input
                id="api-key-secret"
                readOnly
                value={step.secret}
                className="input-field font-mono text-xs"
                onFocus={(event) => event.target.select()}
                autoComplete="off"
                spellCheck={false}
              />
              <Button type="button" variant="secondary" onClick={() => void copy()}>
                {copied ? <Check className="mr-2 h-4 w-4" aria-hidden="true" /> : <Copy className="mr-2 h-4 w-4" aria-hidden="true" />}
                {copied ? t('apiKeys.copied') : t('apiKeys.copy')}
              </Button>
            </div>
            <p className="mt-2 text-sm text-gray-600">
              {t('apiKeys.createdSummary', { prefix: step.key.key_prefix, date: formatDate(step.key.expires_at, i18n.language) })}
            </p>
          </div>
          <label className="flex items-start gap-3 text-sm text-gray-800">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 accent-brand-600"
              checked={step.stored}
              onChange={(event) => dispatch({ type: 'stored', value: event.target.checked })}
            />
            {t('apiKeys.stored')}
          </label>
          <div className="flex justify-end">
            <Button onClick={close} disabled={!step.stored}>
              {t('apiKeys.done')}
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog key="form" open={open} onClose={close} title={t('admin.createApiKey')}>
      <form
        className="space-y-4"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Input
          id="api-key-name"
          label={t('common.name')}
          placeholder={t('admin.apiKeyNamePlaceholder')}
          value={form.name}
          maxLength={MAX_KEY_NAME}
          autoComplete="off"
          onChange={(event) => setForm({ ...form, name: event.target.value })}
          error={nameError}
        />
        <fieldset aria-describedby={touched && problems.includes('scopes') ? 'api-key-scopes-error' : undefined}>
          <legend className="text-sm font-medium text-gray-700">{t('admin.scopes')}</legend>
          <div className="mt-2 space-y-2">
            {API_KEY_SCOPES.map((scope) => (
              <label key={scope} className="flex items-start gap-3">
                <input
                  type="checkbox"
                  className="mt-1 h-4 w-4 accent-brand-600"
                  checked={form.scopes.includes(scope)}
                  onChange={() => setForm({ ...form, scopes: toggleScope(form.scopes, scope) })}
                />
                <span>
                  <code className="block text-sm text-gray-900">{scope}</code>
                  <span className="block text-sm text-gray-600">{t(`apiKeys.scope.${scope.replace(':', '_')}`)}</span>
                </span>
              </label>
            ))}
          </div>
          {touched && problems.includes('scopes') && (
            <p id="api-key-scopes-error" className="mt-2 text-sm text-red-600">
              {t('apiKeys.scopesRequired')}
            </p>
          )}
        </fieldset>
        <Select
          label={t('apiKeys.expiry')}
          value={String(form.days)}
          onChange={(event) => setForm({ ...form, days: Number(event.target.value) })}
          options={KEY_DAY_CHOICES.map((days) => ({ value: String(days), label: t('common.days', { count: days }) }))}
          hint={t('apiKeys.expiryHint')}
        />
        <p className="text-sm text-gray-600">{t('admin.apiKeyShownOnce')}</p>
        {error !== null && (isAccessProblem(error) ? <AdminAccessNote error={error} /> : <Alert>{errorMessage(error, t)}</Alert>)}
        <div className="flex justify-end gap-3">
          <Button type="button" variant="secondary" onClick={close}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" loading={busy}>
            {t('common.create')}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function RevokeKeyDialog({ apiKey, onClose }: { apiKey: ApiKey | null; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  if (!apiKey) return null;

  const close = () => {
    setError(null);
    onClose();
  };

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      const outcome = await revokeApiKey(apiKey.id);
      toast(
        outcome === 'revoked' ? 'success' : 'warning',
        t(outcome === 'revoked' ? 'apiKeys.revoked' : 'apiKeys.revokeUnconfirmed', { name: apiKey.name }),
      );
      await queryClient.invalidateQueries({ queryKey: adminKeys.apiKeys });
      close();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={close} title={t('apiKeys.revokeTitle')}>
      <div className="space-y-4">
        <p className="text-sm text-gray-700">{t('apiKeys.revokeBody', { name: apiKey.name, prefix: apiKey.key_prefix })}</p>
        {error !== null && <Alert>{errorMessage(error, t)}</Alert>}
        <div className="flex justify-end gap-3">
          <Button variant="secondary" onClick={close} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" onClick={() => void confirm()} loading={busy}>
            {t('apiKeys.revoke')}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
