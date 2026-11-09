import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastContainer } from '@/components/ui';
import { StepUpDialog } from '@/features/auth/StepUpDialog';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <QueryClientProvider client={queryClient}>
      {children}
      <ToastContainer />
      {/* "Confirm it's you": every step-up operation's re-authenticate-and-retry (#232). After the page, so on top. */}
      <StepUpDialog />
    </QueryClientProvider>
  );
}
