import { describe, expect, it } from 'vitest';
import { cn } from './cn';

describe('cn', () => {
  it('drops falsy values', () => {
    const isHidden = false;
    expect(cn('btn', isHidden && 'hidden', undefined, 'btn-primary')).toBe('btn btn-primary');
  });

  it('lets a later Tailwind class win over a conflicting earlier one', () => {
    expect(cn('px-2 py-1', 'px-4')).toBe('py-1 px-4');
  });

  // tailwind-merge 3 knows Tailwind 4's syntax (#134); version 2 kept both classes in each case.
  it('merges Tailwind 4 classes', () => {
    expect(cn('p-2!', 'p-4!')).toBe('p-4!');
    expect(cn('px-2', 'px-(--gap)')).toBe('px-(--gap)');
  });
});
