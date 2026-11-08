import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui';
import type { FileState, Schema, TransferState, UploadRequestState } from '@/api';
import { accessStateVariant, deliveryStateVariant, fileStateVariant, inspectionStateVariant, transferStateVariant } from './states';
import { uploadRequestStateVariant } from './uploadRequests';

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

export function UploadRequestStateBadge({ state }: { state: UploadRequestState }) {
  const { t } = useTranslation();
  return <Badge variant={uploadRequestStateVariant[state]}>{t(`uploadRequestState.${state}`)}</Badge>;
}

export function DeliveryStateBadge({ state }: { state: Schema<'DeliveryState'> }) {
  const { t } = useTranslation();
  return <Badge variant={deliveryStateVariant[state]}>{t(`deliveryState.${state}`)}</Badge>;
}

export function AccessStateBadge({ state }: { state: Schema<'AccessState'> }) {
  const { t } = useTranslation();
  return <Badge variant={accessStateVariant[state]}>{t(`accessState.${state}`)}</Badge>;
}
