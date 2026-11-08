import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { X } from 'lucide-react';
import { Button } from '@/components/ui';
import { addDomain, MAX_DOMAINS, removeDomain, type DomainProblem } from './domains';

/**
 * One of the tenant's domain lists (#217, FR-24): the domains as removable chips and an input to add one, checked in
 * place (`domains.ts`). The list is saved with the rest of the policy.
 */
export function DomainListEditor({
  label,
  hint,
  domains,
  onChange,
  error,
}: {
  label: string;
  hint: string;
  domains: string[];
  onChange: (domains: string[]) => void;
  /** A `422` on this list from the service. */
  error?: string;
}) {
  const { t } = useTranslation();
  const id = useId();
  const [input, setInput] = useState('');
  const [problem, setProblem] = useState<DomainProblem | null>(null);

  const add = () => {
    if (input.trim() === '') return;
    const result = addDomain(domains, input);
    if ('problem' in result) {
      setProblem(result.problem);
      return;
    }
    onChange(result.list);
    setInput('');
    setProblem(null);
  };

  const message = problem ? t(`domains.problem.${problem}`, { max: MAX_DOMAINS }) : error;
  const describedBy = [`${id}-hint`, message ? `${id}-error` : null].filter(Boolean).join(' ');

  return (
    <div className="space-y-2">
      <label htmlFor={`${id}-input`} className="block text-sm font-medium text-gray-700">
        {label}
      </label>
      <p id={`${id}-hint`} className="text-sm text-gray-600">
        {hint}
      </p>
      <div className="flex gap-2">
        <input
          id={`${id}-input`}
          className="input-field"
          placeholder={t('domains.placeholder')}
          autoComplete="off"
          spellCheck={false}
          value={input}
          aria-invalid={message ? true : undefined}
          aria-describedby={describedBy}
          onChange={(event) => {
            setInput(event.target.value);
            setProblem(null);
          }}
          onKeyDown={(event) => {
            // Enter adds the domain instead of submitting the policy form.
            if (event.key === 'Enter') {
              event.preventDefault();
              add();
            }
          }}
        />
        <Button type="button" variant="secondary" onClick={add} aria-label={t('domains.addTo', { list: label })}>
          {t('domains.add')}
        </Button>
      </div>
      {message && (
        <p id={`${id}-error`} className="text-sm text-red-600">
          {message}
        </p>
      )}
      {domains.length === 0 ? (
        <p className="text-sm text-gray-600">{t('domains.empty')}</p>
      ) : (
        <ul className="flex flex-wrap gap-2" aria-label={label}>
          {domains.map((domain) => (
            <li key={domain} className="inline-flex items-center gap-1 rounded-full bg-gray-100 py-1 pl-3 pr-1 text-sm text-gray-800">
              <span>{domain}</span>
              <button
                type="button"
                className="rounded-full p-1 text-gray-600 hover:bg-gray-200 hover:text-gray-900"
                aria-label={t('domains.remove', { domain })}
                onClick={() => onChange(removeDomain(domains, domain))}
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs text-gray-600">{t('domains.count', { count: domains.length, max: MAX_DOMAINS })}</p>
    </div>
  );
}
