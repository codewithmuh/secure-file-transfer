import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { cn } from '@/lib/cn';

export interface MenuItem {
  key: string;
  label: string;
  onSelect: () => void;
  danger?: boolean;
  disabled?: boolean;
}

export interface MenuProps {
  /** The button's accessible name, such as "Actions for aiko@example.co.jp". */
  label: string;
  /** What the button shows: an icon, usually. */
  children: ReactNode;
  items: readonly MenuItem[];
}

/**
 * A menu button (WAI-ARIA menu button pattern, #197): Enter, Space or Down Arrow opens the menu on its first item, Up
 * Arrow on its last; the arrow keys, Home and End move between items; Enter or Space picks one; Escape and Tab close
 * it, Escape back on the button.
 */
export function Menu({ label, children, items }: MenuProps) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const menuId = useId();
  const button = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const enabled = items.map((item, index) => ({ item, index })).filter(({ item }) => !item.disabled);

  useEffect(() => {
    if (!open) return;
    list.current?.querySelectorAll<HTMLElement>('[role="menuitem"]')[active]?.focus();
  }, [open, active]);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!list.current?.contains(event.target as Node) && !button.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onPointer);
    return () => document.removeEventListener('mousedown', onPointer);
  }, [open]);

  const openAt = (where: 'first' | 'last') => {
    if (enabled.length === 0) return;
    setActive((where === 'first' ? enabled[0] : enabled[enabled.length - 1])?.index ?? 0);
    setOpen(true);
  };

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) button.current?.focus();
  };

  const move = (step: number) => {
    const position = enabled.findIndex(({ index }) => index === active);
    const next = enabled[(position + step + enabled.length) % enabled.length];
    if (next) setActive(next.index);
  };

  const pick = (item: MenuItem) => {
    close(true);
    item.onSelect();
  };

  return (
    <div className="relative inline-block text-left">
      <button
        ref={button}
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => (open ? close(false) : openAt('first'))}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown' || event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            openAt('first');
          } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            openAt('last');
          }
        }}
        className="rounded-sm p-1 text-gray-500 hover:bg-gray-100 hover:text-gray-700"
      >
        {children}
      </button>
      {open && (
        <ul
          ref={list}
          id={menuId}
          role="menu"
          aria-label={label}
          className="absolute right-0 z-30 mt-1 min-w-48 rounded-lg bg-white py-1 shadow-lg ring-1 ring-gray-950/10"
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') {
              event.preventDefault();
              move(1);
            } else if (event.key === 'ArrowUp') {
              event.preventDefault();
              move(-1);
            } else if (event.key === 'Home') {
              event.preventDefault();
              setActive(enabled[0]?.index ?? 0);
            } else if (event.key === 'End') {
              event.preventDefault();
              setActive(enabled[enabled.length - 1]?.index ?? 0);
            } else if (event.key === 'Escape') {
              event.preventDefault();
              close(true);
            } else if (event.key === 'Tab') {
              close(false);
            }
          }}
        >
          {items.map((item, index) => (
            <li key={item.key} role="none">
              <button
                type="button"
                role="menuitem"
                tabIndex={index === active ? 0 : -1}
                disabled={item.disabled}
                aria-disabled={item.disabled || undefined}
                onClick={() => pick(item)}
                className={cn(
                  'block w-full px-4 py-2 text-left text-sm hover:bg-gray-100 focus:bg-gray-100 focus:outline-none disabled:cursor-not-allowed disabled:text-gray-400',
                  item.danger ? 'text-red-700' : 'text-gray-700',
                )}
              >
                {item.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
