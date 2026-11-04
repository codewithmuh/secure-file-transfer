import { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import { FullPageSpinner } from '@/components/ui';
import { restoreMemberSession } from './memberSession';
import { routeAccess } from './routeAccess';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: 'admin' | 'member';
}

export function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
  const memberStatus = useAuthStore((s) => s.memberStatus);
  const role = useAuthStore((s) => s.user?.role);
  const location = useLocation();

  // After a refresh or a deep link, ask the API whether the session cookie is still valid before deciding.
  useEffect(() => {
    if (memberStatus === 'unknown') void restoreMemberSession();
  }, [memberStatus]);

  switch (routeAccess(memberStatus, role, requiredRole)) {
    case 'wait':
      return <FullPageSpinner />;
    case 'sign-in':
      return <Navigate to="/sign-in" state={{ from: location }} replace />;
    case 'forbidden':
      return <Navigate to="/" replace />;
    case 'allow':
      return <>{children}</>;
  }
}
