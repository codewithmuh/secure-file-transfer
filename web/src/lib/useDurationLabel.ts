import { useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { durationLabelParts } from './durations';

/** A duration such as `P7D` or `PT12H` as the page's language says it: "7 days", "12時間". */
export function useDurationLabel(): (value: string) => string {
  const { t } = useTranslation();
  return useCallback(
    (value: string) => {
      const { unit, count } = durationLabelParts(value);
      return t(`durations.${unit}`, { count });
    },
    [t],
  );
}
