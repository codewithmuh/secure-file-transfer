import { NavLink, Outlet, useLocation } from 'react-router';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/components/layout';
import { Alert, Spinner } from '@/components/ui';
import { AdminAccessNote } from '@/features/admin/AdminAccessNote';
import { cn } from '@/lib/cn';
import { errorMessage, isAccessProblem } from '@/lib/problems';

const SECTIONS = [
  { to: '/admin/dlp', key: 'settings', end: true, also: null },
  { to: '/admin/dlp/rules', key: 'rules', end: false, also: null },
  // A pattern's own page belongs to this section too: it lists the keyword lists and the patterns (#221).
  { to: '/admin/dlp/keywords', key: 'keywords', end: false, also: '/admin/dlp/patterns' },
  { to: '/admin/dlp/reports', key: 'reports', end: false, also: null },
] as const;

/**
 * The tenant's DLP policy (#218, #221, #222; FR-38 to FR-41, FR-45, FR-55, ADR-0022), for admins: its settings, its
 * rules, its keyword lists and patterns, and the report, each a section with its own address, so a link or the back
 * button lands on the same one. Every write asks for a confirmation that names what changes (`ConfirmChange`).
 */
export function DlpAdminPage() {
  const { t } = useTranslation();
  const { pathname } = useLocation();
  return (
    <PageShell title={t('dlpAdmin.title')} description={t('dlpAdmin.description')}>
      <nav aria-label={t('dlpAdmin.sections')} className="border-b border-gray-200">
        <ul className="-mb-px flex flex-wrap gap-4">
          {SECTIONS.map(({ to, key, end, also }) => (
            <li key={key}>
              <NavLink
                to={to}
                end={end}
                className={({ isActive }) =>
                  cn(
                    'inline-block border-b-2 px-1 pb-3 text-sm font-medium',
                    isActive || (also && pathname.startsWith(also))
                      ? 'border-brand-600 text-brand-700'
                      : 'border-transparent text-gray-600 hover:text-gray-900',
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
