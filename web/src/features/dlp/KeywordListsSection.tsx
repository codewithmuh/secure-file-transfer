import { useState } from 'react';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { Button, Card, EmptyState, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, toast } from '@/components/ui';
import type { DlpDetector } from '@/api';
import { deleteDlpDetector, invalidateDlp, useDlpDetectors, useDlpRules } from '@/hooks/dlp';
import { ConfirmChange } from './ConfirmChange';
import { LoadError, Loading } from './DlpAdminPage';
import { detectorRouteId, keywordLists, MAX_PATTERNS, patterns } from './dlpForms';
import { useWrite } from './useWrite';

/**
 * The tenant's keyword lists and patterns (#218, #221; FR-38, FR-39): each list with how many terms it has, each
 * pattern with its expression, and how many rules use each. The terms themselves are shown only on a list's own page.
 * A list or pattern a rule uses can't be deleted (`409 detector_in_use`). A tenant has at most 20 patterns.
 */
export function KeywordListsSection() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const detectors = useDlpDetectors();
  const rules = useDlpRules();
  const [deleting, setDeleting] = useState<DlpDetector | null>(null);
  const write = useWrite();

  if (detectors.isPending) return <Loading />;
  if (detectors.isError) return <LoadError error={detectors.error} />;

  const lists = keywordLists(detectors.data.items);
  const ownPatterns = patterns(detectors.data.items);
  const usedBy = (id: string) => rules.data?.items.filter((rule) => rule.detectors.includes(id)).length;

  const confirm = async () => {
    if (!deleting) return;
    const ok = await write.run(async () => {
      await deleteDlpDetector(deleting.id);
      await invalidateDlp(queryClient);
    });
    if (ok) {
      toast('success', t(deleting.kind === 'pattern' ? 'dlpAdmin.patternDeleted' : 'dlpAdmin.keywordListDeleted', { name: deleting.name }));
      setDeleting(null);
    }
  };

  const remove = (detector: DlpDetector) => {
    write.reset();
    setDeleting(detector);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-gray-600">{t('dlpAdmin.keywordListsHint')}</p>
        <div className="flex flex-wrap gap-2">
          <Link to="/admin/dlp/keywords/new" className="btn-primary">
            <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
            {t('dlpAdmin.addKeywordList')}
          </Link>
          {ownPatterns.length < MAX_PATTERNS && (
            <Link to="/admin/dlp/patterns/new" className="btn-secondary">
              <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
              {t('dlpAdmin.addPattern')}
            </Link>
          )}
        </div>
      </div>

      <h2 className="text-base font-semibold text-gray-900">{t('dlpAdmin.keywordLists')}</h2>

      <Card padding={false}>
        {lists.length === 0 ? (
          <EmptyState title={t('dlpAdmin.noKeywordLists')} description={t('dlpAdmin.noKeywordListsHint')} />
        ) : (
          <Table label={t('dlpAdmin.keywordLists')} caption={t('dlpAdmin.keywordListsCaption')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.name')}</TableHeader>
                <TableHeader>{t('dlpAdmin.terms')}</TableHeader>
                <TableHeader>{t('dlpAdmin.usedBy')}</TableHeader>
                <TableHeader>
                  <span className="sr-only">{t('common.actions')}</span>
                </TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {lists.map((list) => {
                const used = usedBy(list.id);
                return (
                  <TableRow key={list.id}>
                    <th scope="row" className="px-4 py-3 text-left text-sm font-medium text-gray-900">
                      {list.name}
                    </th>
                    <TableCell>{t('dlpAdmin.termCount', { count: list.keywords?.length ?? 0 })}</TableCell>
                    <TableCell>{used === undefined ? '—' : t('dlpAdmin.ruleCount', { count: used })}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap justify-end gap-2">
                        <Link
                          to={`/admin/dlp/keywords/${detectorRouteId(list.id)}`}
                          className="btn-secondary px-3 py-1.5 text-xs"
                          aria-label={t('dlpAdmin.editNamed', { name: list.name })}
                        >
                          {t('dlpAdmin.edit')}
                        </Link>
                        <Button
                          size="sm"
                          variant="danger"
                          aria-label={t('dlpAdmin.deleteNamed', { name: list.name })}
                          onClick={() => remove(list)}
                        >
                          {t('common.delete')}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold text-gray-900">{t('dlpAdmin.patterns')}</h2>
        <p className="text-sm text-gray-600" aria-live="polite">
          {t('dlpAdmin.patternCount', { count: ownPatterns.length, max: MAX_PATTERNS })}
        </p>
      </div>
      <Card padding={false}>
        {ownPatterns.length === 0 ? (
          <EmptyState title={t('dlpAdmin.noPatterns')} description={t('dlpAdmin.noPatternsHint')} />
        ) : (
          <Table label={t('dlpAdmin.patterns')} caption={t('dlpAdmin.patternsCaption')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.name')}</TableHeader>
                <TableHeader>{t('dlpAdmin.pattern')}</TableHeader>
                <TableHeader>{t('dlpAdmin.usedBy')}</TableHeader>
                <TableHeader>
                  <span className="sr-only">{t('common.actions')}</span>
                </TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {ownPatterns.map((pattern) => {
                const used = usedBy(pattern.id);
                return (
                  <TableRow key={pattern.id}>
                    <th scope="row" className="px-4 py-3 text-left text-sm font-medium text-gray-900">
                      {pattern.name}
                    </th>
                    <TableCell className="whitespace-normal">
                      <code className="break-all text-xs">{pattern.pattern}</code>
                    </TableCell>
                    <TableCell>{used === undefined ? '—' : t('dlpAdmin.ruleCount', { count: used })}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap justify-end gap-2">
                        <Link
                          to={`/admin/dlp/patterns/${detectorRouteId(pattern.id)}`}
                          className="btn-secondary px-3 py-1.5 text-xs"
                          aria-label={t('dlpAdmin.editNamed', { name: pattern.name })}
                        >
                          {t('dlpAdmin.edit')}
                        </Link>
                        <Button
                          size="sm"
                          variant="danger"
                          aria-label={t('dlpAdmin.deleteNamed', { name: pattern.name })}
                          onClick={() => remove(pattern)}
                        >
                          {t('common.delete')}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      {deleting && (
        <ConfirmChange
          open
          title={t(deleting.kind === 'pattern' ? 'dlpAdmin.confirmDeletePattern' : 'dlpAdmin.confirmDeleteKeywordList')}
          lines={[
            deleting.kind === 'pattern'
              ? t('dlpAdmin.change.deletePattern', { name: deleting.name })
              : t('dlpAdmin.change.deleteKeywordList', { name: deleting.name, count: deleting.keywords?.length ?? 0 }),
          ]}
          action={t('common.delete')}
          danger
          busy={write.busy}
          error={write.error}
          onConfirm={() => void confirm()}
          onClose={() => setDeleting(null)}
          onReload={() => {
            setDeleting(null);
            void invalidateDlp(queryClient);
          }}
        />
      )}
    </div>
  );
}
