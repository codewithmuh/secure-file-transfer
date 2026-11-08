import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { Clock } from 'lucide-react';

/**
 * What an M5 route shows (#195's decision): upload requests, the audit log and API keys are hidden from the
 * navigation, and an old bookmark or a typed URL gets this clear answer instead of a 404 or mock data.
 * Their components stay in the repository, unrouted, as M5's starting point.
 */
export function NotAvailableYet() {
  const { t } = useTranslation();
  return (
    <div className="mx-auto max-w-lg py-12 text-center">
      <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-gray-100">
        <Clock className="h-6 w-6 text-gray-500" aria-hidden="true" />
      </div>
      <h1 className="text-2xl font-bold text-gray-900">{t('notAvailable.title')}</h1>
      <p className="mt-2 text-sm text-gray-600">{t('notAvailable.body')}</p>
      <Link to="/" className="mt-6 inline-block text-sm font-semibold text-brand-700 hover:text-brand-800 underline">
        {t('notAvailable.home')}
      </Link>
    </div>
  );
}
