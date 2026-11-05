import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/components/layout';
import { Card, CardTitle, Button, Input, toast } from '@/components/ui';

export function TenantPolicyPage() {
  const { t } = useTranslation();
  const [maxExpiryHours, setMaxExpiryHours] = useState('720');
  const [allowUnscannable, setAllowUnscannable] = useState(false);
  const [retentionDays, setRetentionDays] = useState('30');
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    await new Promise((resolve) => setTimeout(resolve, 500));
    toast('success', t('admin.policyUpdated'));
    setSaving(false);
  };

  return (
    <PageShell title={t('admin.tenantPolicy')}>
      <div className="mx-auto max-w-2xl space-y-6">
        <Card>
          <CardTitle>{t('admin.transferSettings')}</CardTitle>
          <div className="mt-4 space-y-4">
            <div>
              <label htmlFor="max-expiry" className="block text-sm font-medium text-gray-700">{t('admin.maxExpiry')}</label>
              <select id="max-expiry" className="input-field mt-1" value={maxExpiryHours} onChange={(e) => setMaxExpiryHours(e.target.value)}>
                <option value="24">{t('common.days', { count: 1 })}</option>
                <option value="168">{t('common.days', { count: 7 })}</option>
                <option value="336">{t('common.days', { count: 14 })}</option>
                <option value="720">{t('common.days', { count: 30 })}</option>
              </select>
            </div>
          </div>
        </Card>

        <Card>
          <CardTitle>{t('admin.security')}</CardTitle>
          <div className="mt-4">
            <div className="flex items-center justify-between">
              <div>
                <p id="unscannable-policy" className="text-sm font-medium text-gray-700">{t('admin.unscannablePolicy')}</p>
                <p className="text-xs text-gray-500">{t('admin.unscannableHint')}</p>
              </div>
              <button
                type="button"
                role="switch"
                aria-labelledby="unscannable-policy"
                aria-checked={allowUnscannable}
                onClick={() => setAllowUnscannable(!allowUnscannable)}
                className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${allowUnscannable ? 'bg-brand-600' : 'bg-gray-200'}`}
              >
                <span className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-sm ring-0 transition ${allowUnscannable ? 'translate-x-5' : 'translate-x-0'}`} />
              </button>
            </div>
          </div>
        </Card>

        <Card>
          <CardTitle>{t('sender.uploadRequests')}</CardTitle>
          <div className="mt-4">
            <Input
              label={t('admin.retentionPeriod')}
              type="number"
              min="1"
              max="90"
              value={retentionDays}
              onChange={(e) => setRetentionDays(e.target.value)}
              helperText={t('admin.retentionHint')}
            />
          </div>
        </Card>

        <Button onClick={handleSave} loading={saving} className="w-full">{t('common.save')}</Button>
      </div>
    </PageShell>
  );
}
