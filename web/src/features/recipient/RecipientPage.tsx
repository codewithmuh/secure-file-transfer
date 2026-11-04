import { useState } from 'react';
import { VerificationPage } from './VerificationPage';
import { RecipientDownloadPage } from './RecipientDownloadPage';

export function RecipientPage() {
  const [verified, setVerified] = useState(false);

  if (!verified) {
    return <VerificationPage mode="recipient" onVerified={() => setVerified(true)} />;
  }

  return <RecipientDownloadPage />;
}
