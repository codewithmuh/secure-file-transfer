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
});
