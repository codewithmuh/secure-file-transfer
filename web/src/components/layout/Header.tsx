import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { useUIStore } from '@/stores/uiStore';
import { Menu, LogOut, Shield } from 'lucide-react';

export function Header() {
  const { t } = useTranslation();
  const { user, clearAuth } = useAuthStore();
  const { toggleSidebar } = useUIStore();

  const handleSignOut = () => {
    clearAuth();
    window.location.href = '/sign-in';
  };

  return (
    <header className="sticky top-0 z-40 border-b border-gray-200 bg-white">
      <div className="flex h-16 items-center gap-4 px-4 sm:px-6">
        <button
          onClick={toggleSidebar}
          className="rounded-lg p-2 text-gray-500 hover:bg-gray-100 lg:hidden"
          aria-label="Toggle sidebar"
        >
          <Menu className="h-5 w-5" />
        </button>

        <div className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-brand-600" />
          <span className="text-lg font-bold text-gray-900">{t('common.appName')}</span>
        </div>

        <div className="ml-auto flex items-center gap-4">
          {user && (
            <>
              <div className="hidden text-right sm:block">
                <p className="text-sm font-medium text-gray-900">{user.name}</p>
                <p className="text-xs text-gray-500">{user.tenantName}</p>
              </div>
              <button
                onClick={handleSignOut}
                className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-gray-600 hover:bg-gray-100"
                title={t('auth.signOut')}
              >
                <LogOut className="h-4 w-4" />
                <span className="hidden sm:inline">{t('auth.signOut')}</span>
              </button>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
