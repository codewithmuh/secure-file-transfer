import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui';
import type { FileState, Schema, TransferState } from '@/api';
import { fileStateVariant, inspectionStateVariant, transferStateVariant } from './states';

export function TransferStateBadge({ state }: { state: TransferState }) {
  const { t } = useTranslation();
  return <Badge variant={transferStateVariant[state]}>{t(`transferState.${state}`)}</Badge>;
}

export function FileStateBadge({ state }: { state: FileState }) {
  const { t } = useTranslation();
  return <Badge variant={fileStateVariant[state]}>{t(`fileState.${state}`)}</Badge>;
}

export function InspectionStateBadge({ state }: { state: Schema<'InspectionState'> }) {
  const { t } = useTranslation();
  return <Badge variant={inspectionStateVariant[state]}>{t(`inspectionState.${state}`)}</Badge>;
}
