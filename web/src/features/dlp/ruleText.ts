import type { TFunction } from 'i18next';
import type { DlpDetector, DlpRule } from '@/api';
import { isBuiltinDetector } from '@/features/sender/states';

/**
 * A detector's name as the page shows it: the API's name (built-in detectors' come in the caller's language), else
 * the app's own for a built-in, else the ID.
 */
export function detectorName(id: string, detectors: readonly DlpDetector[] | undefined, t: TFunction): string {
  const found = detectors?.find((detector) => detector.id === id);
  if (found) return found.name;
  return isBuiltinDetector(id) ? t(`detectors.${id}`) : id;
}

type RuleCondition = Pick<DlpRule, 'condition' | 'detectors' | 'min_confidence' | 'threshold' | 'reasons'>;

/** A rule's condition in a sentence: "My Number: 1 or more at high confidence". */
export function conditionText(rule: RuleCondition, detectors: readonly DlpDetector[] | undefined, t: TFunction): string {
  const separator = t('common.listSeparator');
  switch (rule.condition) {
    case 'content':
      return t('dlpAdmin.conditionContent', {
        detectors: rule.detectors.map((id) => detectorName(id, detectors, t)).join(separator),
        count: rule.threshold,
        confidence: t(`dlpAdmin.confidence.${rule.min_confidence}`),
      });
    case 'not_inspected':
      return t('dlpAdmin.conditionNotInspected', {
        reasons: rule.reasons.map((reason) => t(`dlpAdmin.reason.${reason}`)).join(separator),
      });
    case 'new_domain':
      return t('dlpAdmin.conditionNewDomain');
  }
}
