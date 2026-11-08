import { NavLink, useLocation } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { useUIStore } from '@/stores/uiStore';
import { cn } from '@/lib/cn';
import { seesApprovals } from '@/features/approvals/approvals';
import { usePendingApprovalCount } from '@/hooks/dlp';
import { Inbox, KeyRound, LayoutDashboard, ScrollText, Send, ShieldAlert, ShieldCheck, Users, Settings, X } from 'lucide-react';

// Every M5 page has its entry: upload requests (#212), the audit log (#216), API keys (#215), DLP (#218), approvals (#220).
const memberLinks = [
  { to: '/', icon: LayoutDashboard, labelKey: 'sender.dashboard' },
  { to: '/transfers', icon: Send, labelKey: 'sender.transfers' },
  { to: '/upload-requests', icon: Inbox, labelKey: 'sender.uploadRequests' },
];

const adminLinks = [
  { to: '/admin/users', icon: Users, labelKey: 'admin.users' },
  { to: '/admin/policy', icon: Settings, labelKey: 'admin.tenantPolicy' },
  { to: '/admin/audit', icon: ScrollText, labelKey: 'admin.auditLog' },
  { to: '/admin/api-keys', icon: KeyRound, labelKey: 'admin.apiKeys' },
  { to: '/admin/dlp', icon: ShieldAlert, labelKey: 'dlpAdmin.title' },
];

export function Sidebar() {
  const { t } = useTranslation();
  const { user } = useAuthStore();
  const { sidebarOpen, setSidebarOpen } = useUIStore();
  const location = useLocation();

  const isAdmin = user?.role === 'admin';
  const approvals = seesApprovals(user);
  // The badge counts the approver's own queue (#220); an admin who isn't an approver has no queue.
  const pending = usePendingApprovalCount(Boolean(user?.dlpApprover));
  const pendingText = pending.data ? `${pending.data.count}${pending.data.more ? '+' : ''}` : null;

  return (
    <>
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-gray-200 bg-white transition-transform lg:static lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-16 items-center justify-between border-b border-gray-200 px-4 lg:hidden">
          <span className="text-lg font-bold text-gray-900">{t('common.appName')}</span>
          <button
            onClick={() => setSidebarOpen(false)}
            className="rounded-lg p-2 text-gray-500 hover:bg-gray-100"
            aria-label={t('common.closeSidebar')}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-4">
          <div className="mb-2 px-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
            {t('sender.transfers')}
          </div>
          {memberLinks.map(({ to, icon: Icon, labelKey }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-brand-50 text-brand-700'
                    : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900',
                )
              }
            >
              <Icon className="h-5 w-5" />
              {t(labelKey)}
            </NavLink>
          ))}
          {approvals && (
            <NavLink
              to="/approvals"
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                  isActive || location.pathname.startsWith('/approvals/')
                    ? 'bg-brand-50 text-brand-700'
                    : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900',
                )
              }
            >
              <ShieldCheck className="h-5 w-5" />
              {t('approvals.title')}
              {pendingText !== null && pending.data && pending.data.count > 0 && (
                <span className="ml-auto inline-flex items-center gap-1">
                  <span className="rounded-full bg-red-600 px-2 py-0.5 text-xs font-semibold text-white">{pendingText}</span>
                  <span className="sr-only">{t('approvals.waiting')}</span>
                </span>
              )}
            </NavLink>
          )}

          {isAdmin && (
            <>
              {/* No margin of its own: space-y-1 spaces it, as under Tailwind 3 (which overrode mt-6 mb-2). */}
              <div className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
                {t('admin.title')}
              </div>
              {adminLinks.map(({ to, icon: Icon, labelKey }) => (
                <NavLink
                  key={to}
                  to={to}
                  onClick={() => setSidebarOpen(false)}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                      isActive || location.pathname.startsWith(to)
                        ? 'bg-brand-50 text-brand-700'
                        : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900',
                    )
                  }
                >
                  <Icon className="h-5 w-5" />
                  {t(labelKey)}
                </NavLink>
              ))}
            </>
          )}
        </nav>
      </aside>
    </>
  );
}
