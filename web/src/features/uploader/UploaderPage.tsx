import { useAuthStore } from '@/stores/authStore';
import { VerificationPage } from '@/features/recipient/VerificationPage';
import { UploaderUploadPage } from './UploaderUploadPage';

export function UploaderPage() {
  // Back to the verification step whenever the link session ends, including a 401 from the API.
  const verified = useAuthStore((s) => s.linkSession !== null);

  if (!verified) {
    return <VerificationPage mode="uploader" />;
  }

  return <UploaderUploadPage />;
}
