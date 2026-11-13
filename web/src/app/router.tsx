import type { ComponentType } from 'react';
import { createBrowserRouter, Outlet } from 'react-router';
import { AppLayout, PublicLayout } from '@/components/layout';
import { FullPageSpinner } from '@/components/ui';
import { ProtectedRoute, SignInPage, SignInCallbackPage, StepUpCompletePage } from '@/features/auth';

/**
 * Route-level code splitting (#169): each feature's pages are their own chunk, loaded by the route's `lazy` when it is
 * first visited, so a recipient on `/t` or an uploader on `/u` downloads the shared shell and their own page, never
 * the member and admin pages. The sign-in pages and the layouts stay in the first load: every member starts there.
 * A navigation waits on the current page while the next chunk loads; the first page of a visit shows the spinner.
 */
function page<M>(load: () => Promise<M>, pick: (module: M) => ComponentType): () => Promise<{ Component: ComponentType }> {
  return async () => ({ Component: pick(await load()) });
}

const sender = () => import('@/features/sender');
const recipient = () => import('@/features/recipient');
const uploader = () => import('@/features/uploader');
const admin = () => import('@/features/admin');
const approvals = () => import('@/features/approvals');
const audit = () => import('@/features/audit');
const dlp = () => import('@/features/dlp');

/**
 * The routes. Every M5 page is live: upload requests and the uploader's `/u` (#212, #213), the audit log (#216), API
 * keys (#215), the DLP policy (#218), its patterns (#221) and reports (#222), and approvals (#220).
 */
export const router = createBrowserRouter([
  { path: '/sign-in', element: <SignInPage /> },
  { path: '/auth/callback', element: <SignInCallbackPage /> },
  // The popup of a step-up sign-in lands here, tells the page that opened it, and closes (#232).
  { path: '/auth/step-up-complete', element: <StepUpCompletePage /> },

  {
    element: <PublicLayout />,
    hydrateFallbackElement: <FullPageSpinner />,
    children: [
      { path: '/t', lazy: page(recipient, (m) => m.RecipientPage) },
      { path: '/u', lazy: page(uploader, (m) => m.UploaderPage) },
    ],
  },

  {
    element: (
      <ProtectedRoute>
        <AppLayout />
      </ProtectedRoute>
    ),
    hydrateFallbackElement: <FullPageSpinner />,
    children: [
      { index: true, lazy: page(sender, (m) => m.DashboardPage) },
      { path: '/transfers', lazy: page(sender, (m) => m.TransferListPage) },
      { path: '/transfers/new', lazy: page(sender, (m) => m.CreateTransferPage) },
      { path: '/transfers/:id', lazy: page(sender, (m) => m.TransferDetailPage) },
      { path: '/upload-requests', lazy: page(sender, (m) => m.UploadRequestListPage) },
      { path: '/upload-requests/new', lazy: page(sender, (m) => m.CreateUploadRequestPage) },
      { path: '/upload-requests/:id', lazy: page(sender, (m) => m.UploadRequestDetailPage) },
      // Approvers see their queue, admins every request; a sender may open their own request's page.
      { path: '/approvals', lazy: page(approvals, (m) => m.ApprovalQueuePage) },
      { path: '/approvals/:id', lazy: page(approvals, (m) => m.ApprovalRequestPage) },
      {
        element: (
          <ProtectedRoute requiredRole="admin">
            <Outlet />
          </ProtectedRoute>
        ),
        children: [
          { path: '/admin/users', lazy: page(admin, (m) => m.UserManagementPage) },
          { path: '/admin/policy', lazy: page(admin, (m) => m.TenantPolicyPage) },
          { path: '/admin/audit', lazy: page(audit, (m) => m.AuditLogPage) },
          { path: '/admin/api-keys', lazy: page(admin, (m) => m.ApiKeysPage) },
          { path: '/admin/sso', lazy: page(admin, (m) => m.SsoPage) },
          {
            path: '/admin/dlp',
            lazy: page(dlp, (m) => m.DlpAdminPage),
            children: [
              { index: true, lazy: page(dlp, (m) => m.SettingsSection) },
              { path: 'rules', lazy: page(dlp, (m) => m.RulesSection) },
              { path: 'rules/new', lazy: page(dlp, (m) => m.RuleEditor) },
              { path: 'rules/:ruleId', lazy: page(dlp, (m) => m.RuleEditor) },
              { path: 'keywords', lazy: page(dlp, (m) => m.KeywordListsSection) },
              { path: 'keywords/new', lazy: page(dlp, (m) => m.KeywordListEditor) },
              { path: 'keywords/:detectorId', lazy: page(dlp, (m) => m.KeywordListEditor) },
              { path: 'patterns/new', lazy: page(dlp, (m) => m.PatternEditor) },
              { path: 'patterns/:detectorId', lazy: page(dlp, (m) => m.PatternEditor) },
              { path: 'reports', lazy: page(dlp, (m) => m.DlpReportsSection) },
            ],
          },
        ],
      },
    ],
  },
]);
