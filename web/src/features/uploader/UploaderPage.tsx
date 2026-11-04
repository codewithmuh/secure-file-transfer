import { useState } from 'react';
import { VerificationPage } from '@/features/recipient/VerificationPage';
import { UploaderUploadPage } from './UploaderUploadPage';

export function UploaderPage() {
  const [verified, setVerified] = useState(false);

  if (!verified) {
    return <VerificationPage mode="uploader" onVerified={() => setVerified(true)} />;
  }

  return <UploaderUploadPage />;
}
