import { LinkGate } from '@/features/recipient/LinkGate';
import { UploaderUploadPage } from './UploaderUploadPage';

/**
 * `/u`: the uploader's link page (#212, #213). The same gate as `/t` resolves the link, switches to its language and
 * verifies the uploader (#198); the request and its uploads come once verified.
 */
export function UploaderPage() {
  return (
    <LinkGate mode="uploader">{(session, actions) => <UploaderUploadPage session={session} actions={actions} />}</LinkGate>
  );
}
