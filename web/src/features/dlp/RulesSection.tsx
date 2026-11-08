import { useState } from 'react';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import type { DlpRule } from '@/api';
import { deleteDlpRule, invalidateDlp, updateDlpRule, useDlpDetectors, useDlpPolicy, useDlpRules } from '@/hooks/dlp';
import { dlpActionVariant } from '@/features/sender/states';
import { ConfirmChange } from './ConfirmChange';
import { LoadError, Loading } from './DlpAdminPage';
import { conditionText } from './ruleText';
import { useWrite } from './useWrite';

type Pending = { kind: 'toggle' | 'delete'; rule: DlpRule };

/**
 * The tenant's rules (#218; FR-40, FR-41): each with its condition, recipients, action and whether it is on. A rule is
 * turned on or off, edited or deleted from its row; the default policy's new-domain rule is edited like any other.
 */
export function RulesSection() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const rules = useDlpRules();
  const detectors = useDlpDetectors();
  const policy = useDlpPolicy();
  const [pending, setPending] = useState<Pending | null>(null);
  const write = useWrite();

  if (rules.isPending || policy.isPending) return <Loading />;
  if (rules.isError) return <LoadError error={rules.error} />;
  if (policy.isError) return <LoadError error={policy.error} />;

  const version = policy.data.version;
  const items = rules.data.items;

  const open = (next: Pending) => {
    write.reset();
    setPending(next);
  };

  const confirm = async () => {
    if (!pending) return;
    const { kind, rule } = pending;
    const ok = await write.run(async () => {
      if (kind === 'delete') await deleteDlpRule(rule.id);
      else await updateDlpRule(rule.id, { enabled: !rule.enabled, expected_version: version });
      await invalidateDlp(queryClient);
    });
    if (ok) {
      setPending(null);
      toast(
        'success',
        kind === 'delete'
          ? t('dlpAdmin.ruleDeleted', { name: rule.name })
          : t(rule.enabled ? 'dlpAdmin.ruleTurnedOff' : 'dlpAdmin.ruleTurnedOn', { name: rule.name }),
      );
    }
  };

  const dialog = pending && {
    title:
      pending.kind === 'delete'
        ? t('dlpAdmin.confirmDeleteRule')
        : t(pending.rule.enabled ? 'dlpAdmin.confirmTurnOff' : 'dlpAdmin.confirmTurnOn'),
    lines: [
      pending.kind === 'delete'
        ? t('dlpAdmin.change.deleteRule', { name: pending.rule.name })
        : t(pending.rule.enabled ? 'dlpAdmin.change.turnOff' : 'dlpAdmin.change.turnOn', { name: pending.rule.name }),
    ],
    action:
      pending.kind === 'delete' ? t('common.delete') : t(pending.rule.enabled ? 'dlpAdmin.turnOff' : 'dlpAdmin.turnOn'),
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-gray-600">{t('dlpAdmin.rulesHint', { count: policy.data.active_approvers })}</p>
        <Link to="/admin/dlp/rules/new" className="btn-primary">
          <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('dlpAdmin.addRule')}
        </Link>
      </div>

      <Card padding={false}>
        {items.length === 0 ? (
          <EmptyState title={t('dlpAdmin.noRules')} />
        ) : (
          <Table label={t('dlpAdmin.rules')} caption={t('dlpAdmin.rulesCaption')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.name')}</TableHeader>
                <TableHeader>{t('dlpAdmin.condition')}</TableHeader>
                <TableHeader>{t('dlpAdmin.recipients')}</TableHeader>
                <TableHeader>{t('dlpAdmin.action')}</TableHeader>
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>
                  <span className="sr-only">{t('common.actions')}</span>
                </TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {items.map((rule) => (
                <TableRow key={rule.id}>
                  <th scope="row" className="px-4 py-3 text-left text-sm font-medium text-gray-900">
                    {rule.name}
                  </th>
                  <TableCell className="whitespace-normal">{conditionText(rule, detectors.data?.items, t)}</TableCell>
                  <TableCell>{t(`dlpAdmin.scope.${rule.recipient_scope}`)}</TableCell>
                  <TableCell>
                    <Badge variant={dlpActionVariant[rule.action]}>{t(`dlpAction.${rule.action}`)}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={rule.enabled ? 'success' : 'default'}>{t(rule.enabled ? 'dlpAdmin.on' : 'dlpAdmin.off')}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap justify-end gap-2">
                      <Link
                        to={`/admin/dlp/rules/${rule.id}`}
                        className="btn-secondary px-3 py-1.5 text-xs"
                        aria-label={t('dlpAdmin.editNamed', { name: rule.name })}
                      >
                        {t('dlpAdmin.edit')}
                      </Link>
                      <Button
                        size="sm"
                        variant="secondary"
                        aria-label={t(rule.enabled ? 'dlpAdmin.turnOffNamed' : 'dlpAdmin.turnOnNamed', { name: rule.name })}
                        onClick={() => open({ kind: 'toggle', rule })}
                      >
                        {t(rule.enabled ? 'dlpAdmin.turnOff' : 'dlpAdmin.turnOn')}
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        aria-label={t('dlpAdmin.deleteNamed', { name: rule.name })}
                        onClick={() => open({ kind: 'delete', rule })}
                      >
                        {t('common.delete')}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {dialog && (
        <ConfirmChange
          open
          title={dialog.title}
          lines={dialog.lines}
          action={dialog.action}
          danger={pending?.kind === 'delete'}
          busy={write.busy}
          error={write.error}
          onConfirm={() => void confirm()}
          onClose={() => setPending(null)}
          onReload={() => {
            setPending(null);
            void invalidateDlp(queryClient);
          }}
        />
      )}
    </div>
  );
}
