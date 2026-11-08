import { LinkGate } from '@/features/recipient/LinkGate';
import { UploaderUploadPage } from './UploaderUploadPage';

/** `/u`, M5's: unrouted until then (#195). The same gate as `/t` resolves and verifies the uploader's link (#198). */
export function UploaderPage() {
  return <LinkGate mode="uploader">{() => <UploaderUploadPage />}</LinkGate>;
}
