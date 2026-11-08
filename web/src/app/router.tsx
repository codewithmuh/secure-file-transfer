import { createBrowserRouter } from 'react-router';
import { AppLayout, PublicLayout } from '@/components/layout';
import { ProtectedRoute, SignInPage, SignInCallbackPage } from '@/features/auth';
import {
  DashboardPage,
  TransferListPage,
  CreateTransferPage,
  TransferDetailPage,
  UploadRequestListPage,
  CreateUploadRequestPage,
  UploadRequestDetailPage,
} from '@/features/sender';
import { RecipientPage } from '@/features/recipient';
import { UploaderPage } from '@/features/uploader';
import { UserManagementPage, TenantPolicyPage, ApiKeysPage } from '@/features/admin';
import { ApprovalQueuePage, ApprovalRequestPage } from '@/features/approvals';
import { AuditLogPage } from '@/features/audit';
import {
  DlpAdminPage,
  DlpReportsSection,
  KeywordListEditor,
  KeywordListsSection,
  PatternEditor,
  RuleEditor,
  RulesSection,
  SettingsSection,
} from '@/features/dlp';

/**
 * The routes. Every M5 page is live: upload requests and the uploader's `/u` (#212, #213), the audit log (#216), API
 * keys (#215), the DLP policy (#218), its patterns (#221) and reports (#222), and approvals (#220).
 */
export const router = createBrowserRouter([
  { path: '/sign-in', element: <SignInPage /> },
  { path: '/auth/callback', element: <SignInCallbackPage /> },

  {
    element: <PublicLayout />,
    children: [
      { path: '/t', element: <RecipientPage /> },
      { path: '/u', element: <UploaderPage /> },
    ],
  },

  {
    element: (
      <ProtectedRoute>
        <AppLayout />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <DashboardPage /> },
      { path: '/transfers', element: <TransferListPage /> },
      { path: '/transfers/new', element: <CreateTransferPage /> },
      { path: '/transfers/:id', element: <TransferDetailPage /> },
      { path: '/upload-requests', element: <UploadRequestListPage /> },
      { path: '/upload-requests/new', element: <CreateUploadRequestPage /> },
      { path: '/upload-requests/:id', element: <UploadRequestDetailPage /> },
      // Approvers see their queue, admins every request; a sender may open their own request's page.
      { path: '/approvals', element: <ApprovalQueuePage /> },
      { path: '/approvals/:id', element: <ApprovalRequestPage /> },
      {
        path: '/admin/users',
        element: <ProtectedRoute requiredRole="admin"><UserManagementPage /></ProtectedRoute>,
      },
      {
        path: '/admin/policy',
        element: <ProtectedRoute requiredRole="admin"><TenantPolicyPage /></ProtectedRoute>,
      },
      {
        path: '/admin/audit',
        element: <ProtectedRoute requiredRole="admin"><AuditLogPage /></ProtectedRoute>,
      },
      {
        path: '/admin/api-keys',
        element: <ProtectedRoute requiredRole="admin"><ApiKeysPage /></ProtectedRoute>,
      },
      {
        path: '/admin/dlp',
        element: <ProtectedRoute requiredRole="admin"><DlpAdminPage /></ProtectedRoute>,
        children: [
          { index: true, element: <SettingsSection /> },
          { path: 'rules', element: <RulesSection /> },
          { path: 'rules/new', element: <RuleEditor /> },
          { path: 'rules/:ruleId', element: <RuleEditor /> },
          { path: 'keywords', element: <KeywordListsSection /> },
          { path: 'keywords/new', element: <KeywordListEditor /> },
          { path: 'keywords/:detectorId', element: <KeywordListEditor /> },
          { path: 'patterns/new', element: <PatternEditor /> },
          { path: 'patterns/:detectorId', element: <PatternEditor /> },
          { path: 'reports', element: <DlpReportsSection /> },
        ],
      },
    ],
  },
]);
