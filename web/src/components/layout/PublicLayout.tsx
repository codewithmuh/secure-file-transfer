import { Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Shield } from 'lucide-react';

export function PublicLayout() {
  const { t } = useTranslation();

  return (
    <div className="flex min-h-screen flex-col bg-gray-50">
      <header className="border-b border-gray-200 bg-white">
        <div className="mx-auto flex h-16 max-w-3xl items-center px-4">
          <Shield className="h-6 w-6 text-brand-600" />
          <span className="ml-2 text-lg font-bold text-gray-900">{t('common.appName')}</span>
        </div>
      </header>
      <main className="flex flex-1 items-start justify-center px-4 py-12">
        <div className="w-full max-w-xl">
          <Outlet />
        </div>
      </main>
      <footer className="border-t border-gray-200 bg-white py-4 text-center text-xs text-gray-400">
        {t('common.appName')}
      </footer>
    </div>
  );
}
