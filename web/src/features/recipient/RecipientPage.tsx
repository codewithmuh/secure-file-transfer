import { LinkGate } from './LinkGate';
import { RecipientDownloadPage } from './RecipientDownloadPage';

/** `/t`: the recipient's link page (#198). The gate resolves and verifies; the files come once verified. */
export function RecipientPage() {
  return (
    <LinkGate mode="recipient">
      {(session, actions) => <RecipientDownloadPage session={session} actions={actions} />}
    </LinkGate>
  );
}
