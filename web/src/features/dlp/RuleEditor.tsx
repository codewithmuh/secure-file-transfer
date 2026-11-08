import { useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft } from 'lucide-react';
import { Alert, Button, Card, CardTitle, Input, Select, toast } from '@/components/ui';
import type { DlpDetector, DlpPolicy, DlpRule } from '@/api';
import { createDlpRule, invalidateDlp, updateDlpRule, useDlpDetectors, useDlpPolicy, useDlpRules } from '@/hooks/dlp';
import { IdempotencyKeys, mayHaveHappened } from '@/lib/idempotency';
import { ConfirmChange } from './ConfirmChange';
import { LoadError, Loading } from './DlpAdminPage';
import {
  actionsFor,
  builtInDetectors,
  CONFIDENCES,
  CREATABLE_CONDITIONS,
  DIRECTIONS,
  effectiveRuleOptions,
  emptyRuleForm,
  keywordLists,
  offersSender24h,
  patterns,
  REASONS,
  RULE_NAME_MAX,
  ruleCreateBody,
  ruleFormOf,
  ruleProblems,
  ruleUpdate,
  THRESHOLD_MAX,
  withDirection,
  type RuleChange,
  type RuleForm,
} from './dlpForms';
import { conditionText, detectorName } from './ruleText';
import { useWrite } from './useWrite';

/**
 * A rule's form (#218, #221; FR-40, FR-41, FR-44, FR-45, FR-49, FR-51), new (`/admin/dlp/rules/new`) or existing
 * (`/admin/dlp/rules/:ruleId`). A new rule is for sent or received files and has a content condition (detectors,
 * keyword lists and patterns, the least confidence and a threshold) or a not-inspected one (reasons); a rule keeps its
 * direction and condition once made. A rule for received files only records or blocks, and has no recipients and no
 * 24-hour window; a content rule for sent files can count the sender's last 24 hours, and a rule that requires
 * approval can ask for two different approvers.
 */
export function RuleEditor() {
  const { ruleId } = useParams<{ ruleId: string }>();
  const { t } = useTranslation();
  const rules = useDlpRules();
  const detectors = useDlpDetectors();
  const policy = useDlpPolicy();

  if (rules.isPending || detectors.isPending || policy.isPending) return <Loading />;
  for (const query of [rules, detectors, policy]) if (query.isError) return <LoadError error={query.error} />;
  if (!rules.data || !detectors.data || !policy.data) return null;

  const rule = ruleId ? rules.data.items.find((item) => item.id === ruleId) : undefined;
  if (ruleId && !rule) return <Alert>{t('dlpAdmin.ruleNotFound')}</Alert>;
  return <RuleFormView key={rule ? `${rule.id}:${rule.revision}` : 'new'} rule={rule} detectors={detectors.data.items} policy={policy.data} />;
}

function RuleFormView({ rule, detectors, policy }: { rule: DlpRule | undefined; detectors: DlpDetector[]; policy: DlpPolicy }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<RuleForm>(() => (rule ? ruleFormOf(rule) : emptyRuleForm));
  // The version this form was loaded at: a write after another admin's change gets 409 dlp_policy_conflict.
  const [version] = useState(policy.version);
  const [shown, setShown] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const write = useWrite();
  const keys = useRef(new IdempotencyKeys());

  const condition = rule?.condition ?? form.condition;
  const direction = rule?.direction ?? form.direction;
  const problems = ruleProblems({ ...form, condition, direction });
  const options = effectiveRuleOptions({ ...form, condition, direction });
  const update = rule ? ruleUpdate(rule, form, version) : null;
  const createBody = rule ? null : ruleCreateBody(form, version);
  const nothingChanged = rule !== undefined && update !== null && update.changes.length === 0;

  const set = <K extends keyof RuleForm>(key: K, value: RuleForm[K]) => setForm((previous) => ({ ...previous, [key]: value }));
  const setDirection = (value: RuleForm['direction']) => setForm((previous) => withDirection(previous, value));
  const toggle = <K extends 'detectors' | 'reasons'>(key: K, value: RuleForm[K][number]) =>
    setForm((previous) => {
      const list = previous[key] as string[];
      return { ...previous, [key]: list.includes(value) ? list.filter((item) => item !== value) : [...list, value] };
    });

  const lines = useMemo(() => {
    const actionText = t(`dlpAction.${form.action}`);
    if (!rule) {
      return [
        t('dlpAdmin.change.addRule', { name: form.name.trim() }),
        t('dlpAdmin.change.direction', { direction: t(`dlpAdmin.direction.${form.direction}`) }),
        t('dlpAdmin.change.when', { condition: conditionText({ ...form, condition, threshold: Number(form.threshold) }, detectors, t) }),
        ...(options.include_sender_24h ? [t('dlpAdmin.change.with24h')] : []),
        ...(form.direction === 'sent' ? [t('dlpAdmin.change.recipients', { scope: t(`dlpAdmin.scope.${form.recipient_scope}`) })] : []),
        t('dlpAdmin.change.then', { action: actionText }),
        ...(options.approvals_required === 2 ? [t('dlpAdmin.change.twoApprovers')] : []),
        ...(form.enabled ? [] : [t('dlpAdmin.change.createdOff')]),
      ];
    }
    const describe = (change: RuleChange): string => {
      switch (change) {
        case 'name':
          return t('dlpAdmin.change.rename', { from: rule.name, to: form.name.trim() });
        case 'enabled':
          return t(form.enabled ? 'dlpAdmin.change.turnOn' : 'dlpAdmin.change.turnOff', { name: rule.name });
        case 'detectors': {
          const added = form.detectors.filter((id) => !rule.detectors.includes(id));
          const removed = rule.detectors.filter((id) => !form.detectors.includes(id));
          const names = (ids: string[]) => ids.map((id) => detectorName(id, detectors, t)).join(t('common.listSeparator'));
          return [
            added.length ? t('dlpAdmin.change.detectorsAdded', { names: names(added) }) : '',
            removed.length ? t('dlpAdmin.change.detectorsRemoved', { names: names(removed) }) : '',
          ]
            .filter(Boolean)
            .join(' ');
        }
        case 'min_confidence':
          return t('dlpAdmin.change.confidence', {
            from: t(`dlpAdmin.confidence.${rule.min_confidence}`),
            to: t(`dlpAdmin.confidence.${form.min_confidence}`),
          });
        case 'threshold':
          return t('dlpAdmin.change.threshold', { from: rule.threshold, to: form.threshold.trim() });
        case 'reasons':
          return t('dlpAdmin.change.reasons', {
            reasons: form.reasons.map((reason) => t(`dlpAdmin.reason.${reason}`)).join(t('common.listSeparator')),
          });
        case 'recipient_scope':
          return t('dlpAdmin.change.scope', {
            from: t(`dlpAdmin.scope.${rule.recipient_scope}`),
            to: t(`dlpAdmin.scope.${form.recipient_scope}`),
          });
        case 'action':
          return t('dlpAdmin.change.action', { from: t(`dlpAction.${rule.action}`), to: actionText });
        case 'include_sender_24h':
          return t(options.include_sender_24h ? 'dlpAdmin.change.with24h' : 'dlpAdmin.change.without24h');
        case 'approvals_required':
          return t('dlpAdmin.change.approvers', { from: rule.approvals_required, to: options.approvals_required });
      }
    };
    return [t('dlpAdmin.change.editRule', { name: rule.name }), ...(update?.changes ?? []).map(describe)];
  }, [rule, form, condition, options, detectors, update, t]);

  const submit = () => {
    setShown(true);
    if (Object.keys(problems).length > 0 || nothingChanged) return;
    write.reset();
    setConfirming(true);
  };

  const save = async () => {
    const ok = await write.run(async () => {
      if (rule && update) {
        await updateDlpRule(rule.id, update.body);
      } else if (createBody) {
        try {
          await createDlpRule(createBody, keys.current.keyForBody('createDlpRule', createBody));
          keys.current.done('createDlpRule');
        } catch (failure) {
          if (!mayHaveHappened(failure)) keys.current.done('createDlpRule');
          throw failure;
        }
      }
      await invalidateDlp(queryClient);
    });
    if (ok) {
      setConfirming(false);
      toast('success', t(rule ? 'dlpAdmin.ruleSaved' : 'dlpAdmin.ruleAdded', { name: form.name.trim() }));
      navigate('/admin/dlp/rules');
    }
  };

  const fieldError = (field: keyof typeof problems) => (shown && problems[field] ? t(`dlpAdmin.ruleProblem.${problems[field]}`) : undefined);
  const builtIns = builtInDetectors(detectors);
  const lists = keywordLists(detectors);
  const ownPatterns = patterns(detectors);
  const actions = actionsFor(direction);

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
          <h2 className="text-lg font-semibold text-gray-900">{rule ? t('dlpAdmin.editRule') : t('dlpAdmin.addRule')}</h2>
          <Link to="/admin/dlp/rules" className="btn-secondary">
            <ArrowLeft className="mr-2 h-4 w-4" aria-hidden="true" />
            {t('dlpAdmin.backToRules')}
          </Link>
        </div>

        <Card>
          <div className="space-y-4">
            <Input
              id="rule-name"
              label={t('common.name')}
              value={form.name}
              maxLength={RULE_NAME_MAX}
              onChange={(event) => set('name', event.target.value)}
              error={fieldError('name')}
            />
            <label className="flex items-center gap-3 text-sm text-gray-900">
              <input
                type="checkbox"
                className="h-4 w-4 accent-brand-600"
                checked={form.enabled}
                onChange={(event) => set('enabled', event.target.checked)}
              />
              {t('dlpAdmin.ruleEnabled')}
            </label>
          </div>
        </Card>

        <Card>
          {rule ? (
            <>
              <CardTitle>{t('dlpAdmin.appliesTo')}</CardTitle>
              <p className="mt-3 text-sm text-gray-700">{t(`dlpAdmin.direction.${rule.direction}`)}</p>
            </>
          ) : (
            <fieldset>
              <legend className="text-lg font-semibold text-gray-900">{t('dlpAdmin.appliesTo')}</legend>
              <div className="mt-3 space-y-3">
                {DIRECTIONS.map((value) => (
                  <label key={value} className="flex items-start gap-3">
                    <input
                      type="radio"
                      name="direction"
                      value={value}
                      checked={form.direction === value}
                      onChange={() => setDirection(value)}
                      className="mt-1 h-4 w-4 accent-brand-600"
                    />
                    <span>
                      <span className="block text-sm font-medium text-gray-900">{t(`dlpAdmin.direction.${value}`)}</span>
                      <span className="block text-sm text-gray-600">{t(`dlpAdmin.directionHint.${value}`)}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
          )}
        </Card>

        <Card>
          <CardTitle>{t('dlpAdmin.condition')}</CardTitle>
          {rule ? (
            <p className="mt-3 text-sm text-gray-700">{t(`dlpAdmin.conditionKind.${rule.condition}`)}</p>
          ) : (
            <fieldset className="mt-3">
              <legend className="sr-only">{t('dlpAdmin.condition')}</legend>
              <div className="space-y-3">
                {CREATABLE_CONDITIONS.map((value) => (
                  <label key={value} className="flex items-start gap-3">
                    <input
                      type="radio"
                      name="condition"
                      value={value}
                      checked={form.condition === value}
                      onChange={() => set('condition', value)}
                      className="mt-1 h-4 w-4 accent-brand-600"
                    />
                    <span>
                      <span className="block text-sm font-medium text-gray-900">{t(`dlpAdmin.conditionKind.${value}`)}</span>
                      <span className="block text-sm text-gray-600">{t(`dlpAdmin.conditionHint.${value}`)}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
          )}

          {condition === 'content' && (
            <div className="mt-5 space-y-5">
              <DetectorChoices
                legend={t('dlpAdmin.builtInDetectors')}
                detectors={builtIns}
                selected={form.detectors}
                onToggle={(id) => toggle('detectors', id)}
                describedBy={fieldError('detectors') ? 'rule-detectors-error' : undefined}
              />
              <DetectorChoices
                legend={t('dlpAdmin.keywordLists')}
                detectors={lists}
                selected={form.detectors}
                onToggle={(id) => toggle('detectors', id)}
                empty={t('dlpAdmin.noKeywordListsYet')}
                describedBy={fieldError('detectors') ? 'rule-detectors-error' : undefined}
              />
              <DetectorChoices
                legend={t('dlpAdmin.patterns')}
                detectors={ownPatterns}
                selected={form.detectors}
                onToggle={(id) => toggle('detectors', id)}
                empty={t('dlpAdmin.noPatternsYet')}
                describedBy={fieldError('detectors') ? 'rule-detectors-error' : undefined}
              />
              {fieldError('detectors') && (
                <p id="rule-detectors-error" className="text-sm text-red-600">
                  {fieldError('detectors')}
                </p>
              )}
              <div className="grid gap-4 sm:grid-cols-2">
                <Select
                  label={t('dlpAdmin.minConfidence')}
                  value={form.min_confidence}
                  onChange={(event) => set('min_confidence', event.target.value as RuleForm['min_confidence'])}
                  options={CONFIDENCES.map((value) => ({ value, label: t(`dlpAdmin.confidence.${value}`) }))}
                  hint={t('dlpAdmin.minConfidenceHint')}
                />
                <Input
                  id="rule-threshold"
                  label={t('dlpAdmin.threshold')}
                  inputMode="numeric"
                  value={form.threshold}
                  onChange={(event) => set('threshold', event.target.value)}
                  helperText={t('dlpAdmin.thresholdHint', { max: THRESHOLD_MAX.toLocaleString() })}
                  error={fieldError('threshold')}
                />
              </div>
              {offersSender24h({ direction, condition }) && (
                <label className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    className="mt-1 h-4 w-4 accent-brand-600"
                    checked={form.include_sender_24h}
                    onChange={(event) => set('include_sender_24h', event.target.checked)}
                  />
                  <span>
                    <span className="block text-sm font-medium text-gray-900">{t('dlpAdmin.include24h')}</span>
                    <span className="block text-sm text-gray-600">{t('dlpAdmin.include24hHint')}</span>
                  </span>
                </label>
              )}
            </div>
          )}

          {condition === 'not_inspected' && (
            <fieldset className="mt-5" aria-describedby={fieldError('reasons') ? 'rule-reasons-error' : undefined}>
              <legend className="text-sm font-medium text-gray-700">{t('dlpAdmin.reasons')}</legend>
              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                {REASONS.map((reason) => (
                  <label key={reason} className="flex items-center gap-3 text-sm text-gray-900">
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-brand-600"
                      checked={form.reasons.includes(reason)}
                      onChange={() => toggle('reasons', reason)}
                    />
                    {t(`dlpAdmin.reason.${reason}`)}
                  </label>
                ))}
              </div>
              {fieldError('reasons') && (
                <p id="rule-reasons-error" className="mt-2 text-sm text-red-600">
                  {fieldError('reasons')}
                </p>
              )}
            </fieldset>
          )}
        </Card>

        {direction === 'sent' && (
          <Card>
            <fieldset>
              <legend className="text-lg font-semibold text-gray-900">{t('dlpAdmin.recipients')}</legend>
              <div className="mt-3 space-y-3">
                {(['any', 'untrusted'] as const).map((value) => (
                  <label key={value} className="flex items-start gap-3">
                    <input
                      type="radio"
                      name="recipient_scope"
                      value={value}
                      checked={form.recipient_scope === value}
                      onChange={() => set('recipient_scope', value)}
                      className="mt-1 h-4 w-4 accent-brand-600"
                    />
                    <span className="text-sm text-gray-900">{t(`dlpAdmin.scopeHint.${value}`)}</span>
                  </label>
                ))}
              </div>
            </fieldset>
          </Card>
        )}

        <Card>
          <fieldset aria-describedby={fieldError('action') ? 'rule-action-error' : undefined}>
            <legend className="text-lg font-semibold text-gray-900">{t('dlpAdmin.action')}</legend>
            {direction === 'received' && <p className="mt-1 text-sm text-gray-600">{t('dlpAdmin.receivedActionsHint')}</p>}
            <div className="mt-3 space-y-3">
              {actions.map((value) => (
                <label key={value} className="flex items-start gap-3">
                  <input
                    type="radio"
                    name="action"
                    value={value}
                    checked={form.action === value}
                    onChange={() => set('action', value)}
                    className="mt-1 h-4 w-4 accent-brand-600"
                  />
                  <span>
                    <span className="block text-sm font-medium text-gray-900">{t(`dlpAction.${value}`)}</span>
                    <span className="block text-sm text-gray-600">
                      {t(direction === 'received' ? `dlpAdmin.receivedActionHint.${value}` : `dlpAdmin.actionHint.${value}`)}
                    </span>
                  </span>
                </label>
              ))}
            </div>
            {fieldError('action') && (
              <p id="rule-action-error" className="mt-2 text-sm text-red-600">
                {fieldError('action')}
              </p>
            )}
          </fieldset>
          {direction === 'sent' && form.action === 'require_approval' && (
            <>
              <label className="mt-4 flex items-start gap-3">
                <input
                  type="checkbox"
                  className="mt-1 h-4 w-4 accent-brand-600"
                  checked={form.approvals_required === 2}
                  onChange={(event) => set('approvals_required', event.target.checked ? 2 : 1)}
                />
                <span>
                  <span className="block text-sm font-medium text-gray-900">{t('dlpAdmin.twoApproversOption')}</span>
                  <span className="block text-sm text-gray-600">{t('dlpAdmin.twoApproversHint')}</span>
                </span>
              </label>
              {form.approvals_required === 2 ? (
                <Alert variant={policy.active_approvers < 3 ? 'warning' : 'info'} role="status" className="mt-4">
                  {t('dlpAdmin.twoApproversNeed', { count: policy.active_approvers })}
                </Alert>
              ) : (
                <Alert variant={policy.active_approvers < 2 ? 'warning' : 'info'} role="status" className="mt-4">
                  {t('dlpAdmin.approvalNeedsApprovers', { count: policy.active_approvers })}
                </Alert>
              )}
            </>
          )}
        </Card>

        {nothingChanged && shown && (
          <Alert variant="info" role="status">
            {t('dlpAdmin.nothingChanged')}
          </Alert>
        )}

        <Button type="submit" className="w-full">
          {rule ? t('common.save') : t('dlpAdmin.addRule')}
        </Button>
      </form>

      <ConfirmChange
        open={confirming}
        title={rule ? t('dlpAdmin.confirmEditRule') : t('dlpAdmin.confirmAddRule')}
        lines={lines}
        action={rule ? t('common.save') : t('dlpAdmin.addRule')}
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

function DetectorChoices({
  legend,
  detectors,
  selected,
  onToggle,
  empty,
  describedBy,
}: {
  legend: string;
  detectors: DlpDetector[];
  selected: readonly string[];
  onToggle: (id: string) => void;
  empty?: string;
  describedBy?: string;
}) {
  const { t } = useTranslation();
  return (
    <fieldset aria-describedby={describedBy}>
      <legend className="text-sm font-medium text-gray-700">{legend}</legend>
      {detectors.length === 0 ? (
        <p className="mt-2 text-sm text-gray-600">{empty}</p>
      ) : (
        <div className="mt-2 space-y-2">
          {detectors.map((detector) => (
            <label key={detector.id} className="flex items-start gap-3">
              <input
                type="checkbox"
                className="mt-1 h-4 w-4 accent-brand-600"
                checked={selected.includes(detector.id)}
                onChange={() => onToggle(detector.id)}
              />
              <span>
                <span className="block text-sm text-gray-900">{detector.name}</span>
                {detector.kind === 'built_in' && detector.description && (
                  <span className="block text-xs text-gray-600">{detector.description}</span>
                )}
                {detector.kind === 'keywords' && (
                  <span className="block text-xs text-gray-600">{t('dlpAdmin.termCount', { count: detector.keywords?.length ?? 0 })}</span>
                )}
                {detector.kind === 'pattern' && detector.pattern && (
                  <code className="block break-all text-xs text-gray-600">{detector.pattern}</code>
                )}
              </span>
            </label>
          ))}
        </div>
      )}
    </fieldset>
  );
}
