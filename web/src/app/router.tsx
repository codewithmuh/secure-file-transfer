import { createBrowserRouter } from 'react-router';
import { AppLayout, PublicLayout } from '@/components/layout';
import { ProtectedRoute } from '@/features/auth';
import { SignInPage, SignInCallbackPage } from '@/features/auth';
import { DashboardPage, TransferListPage, CreateTransferPage, TransferDetailPage, UploadRequestListPage, CreateUploadRequestPage } from '@/features/sender';
import { RecipientPage } from '@/features/recipient';
import { UploaderPage } from '@/features/uploader';
import { UserManagementPage, TenantPolicyPage, ApiKeysPage } from '@/features/admin';
import { AuditLogPage } from '@/features/audit';

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
    ],
  },
]);
