import { createBrowserRouter } from 'react-router';
import { AppLayout, PublicLayout } from '@/components/layout';
import { NotAvailableYet } from '@/components/NotAvailableYet';
import { ProtectedRoute, SignInPage, SignInCallbackPage } from '@/features/auth';
import { DashboardPage, TransferListPage, CreateTransferPage, TransferDetailPage } from '@/features/sender';
import { RecipientPage } from '@/features/recipient';
import { UserManagementPage, TenantPolicyPage } from '@/features/admin';

/**
 * The routes. M5's pages (upload requests and the uploader's `/u`, the audit log, API keys and the DLP policy) are
 * hidden (#195's decision): no navigation entry, and their routes show `NotAvailableYet`, so an old bookmark or a typed
 * URL gets a clear answer. Their components stay in the repository, unrouted and unimported, as M5's starting point;
 * M5 routes each again as its operations land.
 */
export const router = createBrowserRouter([
  { path: '/sign-in', element: <SignInPage /> },
  { path: '/auth/callback', element: <SignInCallbackPage /> },

  {
    element: <PublicLayout />,
    children: [
      { path: '/t', element: <RecipientPage /> },
      { path: '/u', element: <NotAvailableYet /> },
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
      { path: '/upload-requests/*', element: <NotAvailableYet /> },
      {
        path: '/admin/users',
        element: <ProtectedRoute requiredRole="admin"><UserManagementPage /></ProtectedRoute>,
      },
      {
        path: '/admin/policy',
        element: <ProtectedRoute requiredRole="admin"><TenantPolicyPage /></ProtectedRoute>,
      },
      { path: '/admin/audit/*', element: <NotAvailableYet /> },
      { path: '/admin/api-keys/*', element: <NotAvailableYet /> },
      { path: '/admin/dlp/*', element: <NotAvailableYet /> },
    ],
  },
]);
