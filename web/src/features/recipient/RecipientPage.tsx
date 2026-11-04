import { useAuthStore } from '@/stores/authStore';
import { VerificationPage } from './VerificationPage';
import { RecipientDownloadPage } from './RecipientDownloadPage';

export function RecipientPage() {
  // Back to the verification step whenever the link session ends, including a 401 from the API.
  const verified = useAuthStore((s) => s.linkSession !== null);

  if (!verified) {
    return <VerificationPage mode="recipient" />;
  }

  return <RecipientDownloadPage />;
}
