import { NavLink, Outlet } from 'react-router';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/components/layout';
import { Alert, Spinner } from '@/components/ui';
import { AdminAccessNote } from '@/features/admin/AdminAccessNote';
import { cn } from '@/lib/cn';
import { errorMessage, isAccessProblem } from '@/lib/problems';

const SECTIONS = [
  { to: '/admin/dlp', key: 'settings', end: true },
  { to: '/admin/dlp/rules', key: 'rules', end: false },
  { to: '/admin/dlp/keywords', key: 'keywords', end: false },
] as const;

/**
 * The tenant's DLP policy (#218; FR-38, FR-40, FR-41, FR-45, ADR-0022), for admins: its settings, its rules and its
 * keyword lists, each a section with its own address, so a link or the back button lands on the same one. Every
 * write asks for a confirmation that names what changes (`ConfirmChange`).
 */
export function DlpAdminPage() {
  const { t } = useTranslation();
  return (
    <PageShell title={t('dlpAdmin.title')} description={t('dlpAdmin.description')}>
      <nav aria-label={t('dlpAdmin.sections')} className="border-b border-gray-200">
        <ul className="-mb-px flex flex-wrap gap-4">
          {SECTIONS.map(({ to, key, end }) => (
            <li key={key}>
              <NavLink
                to={to}
                end={end}
                className={({ isActive }) =>
                  cn(
                    'inline-block border-b-2 px-1 pb-3 text-sm font-medium',
                    isActive ? 'border-brand-600 text-brand-700' : 'border-transparent text-gray-600 hover:text-gray-900',
                  )
                }
              >
                {t(`dlpAdmin.section.${key}`)}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <Outlet />
    </PageShell>
  );
}

/** A section's loading and error states: the step-up or passkey note for an access problem. */
export function Loading() {
  const { t } = useTranslation();
  return (
    <div className="flex justify-center py-12">
      <Spinner />
      <span className="sr-only">{t('common.loading')}</span>
    </div>
  );
}

export function LoadError({ error }: { error: unknown }) {
  const { t } = useTranslation();
  return isAccessProblem(error) ? <AdminAccessNote error={error} /> : <Alert>{errorMessage(error, t)}</Alert>;
}
