import { describe, expect, it } from 'vitest';
import type { SsoDomain, SsoGroupRole, TenantSsoSettings } from '@/api';
import { withDomain, withoutDomain } from '@/hooks/sso';
import {
  addGroupRole,
  changedSsoFields,
  claimDomain,
  domainState,
  formOf,
  groupRolesValid,
  MAX_GROUP_LENGTH,
  MAX_GROUP_ROLES,
  MAX_SSO_DOMAINS,
  removeGroupRole,
  sameGroupRoles,
  setGroupRole,
  ssoRequiredBlockers,
  verifyProblem,
} from './ssoForm';

function domain(name: string, change: Partial<SsoDomain> = {}): SsoDomain {
  return {
    id: `id-${name}`,
    domain: name,
    status: 'pending',
    txt_record_name: `_sft-verification.${name}`,
    txt_record_value: 'sft-domain-verification=placeholder',
    idp_connection_id: null,
    verified_at: null,
    created_at: '2026-11-01T00:00:00Z',
    ...change,
  };
}

const settings: TenantSsoSettings = {
  connection: { id: 'c1', kind: 'saml', provider_name: 'tenant', issuer: null, status: 'active' },
  sso_required: false,
  sso_mfa_confirmed_by: null,
  sso_mfa_confirmed_at: null,
  jit_provisioning: false,
  group_roles: [{ group: 'Staff', role: 'member' }],
  domains: [domain('example.co.jp')],
};

describe('claimDomain (#231)', () => {
  it('normalises the domain as the service stores it', () => {
    expect(claimDomain([], '  Example.COM. ')).toEqual({ domain: 'example.com' });
    expect(claimDomain([], '@example.com')).toEqual({ domain: 'example.com' });
    expect(claimDomain([], '例え.jp')).toEqual({ domain: 'xn--r8jz45g.jp' });
  });

  it.each(['', 'localhost', 'not a domain', 'https://example.com', 'aiko@example.com', '10.0.0.1'])('refuses %j', (input) => {
    expect(claimDomain([], input)).toEqual({ problem: 'invalid' });
  });

  it('refuses a domain the tenant already holds, and more than 20', () => {
    expect(claimDomain([domain('example.co.jp')], 'EXAMPLE.co.jp')).toEqual({ problem: 'duplicate' });
    const full = Array.from({ length: MAX_SSO_DOMAINS }, (_, i) => domain(`d${i}.example`));
    expect(claimDomain(full, 'new.example')).toEqual({ problem: 'tooMany' });
  });
});

describe('domainState', () => {
  it('is pending, verified, then linked once an operator links it', () => {
    expect(domainState(domain('a.example'))).toBe('pending');
    expect(domainState(domain('a.example', { status: 'verified' }))).toBe('verified');
    expect(domainState(domain('a.example', { status: 'verified', idp_connection_id: 'c1' }))).toBe('linked');
  });
});

describe('group mappings: replace semantics, at most 50, each group once', () => {
  const list: SsoGroupRole[] = [{ group: 'Staff', role: 'member' }];

  it('adds a mapping, trimming the name but keeping its case', () => {
    expect(addGroupRole(list, '  IT-Admins ', 'admin')).toEqual({
      list: [...list, { group: 'IT-Admins', role: 'admin' }],
    });
  });

  it('refuses an empty, too long, duplicate group, and a 51st', () => {
    expect(addGroupRole(list, '   ', 'member')).toEqual({ problem: 'empty' });
    expect(addGroupRole(list, 'x'.repeat(MAX_GROUP_LENGTH + 1), 'member')).toEqual({ problem: 'tooLong' });
    expect(addGroupRole(list, 'x'.repeat(MAX_GROUP_LENGTH), 'member')).toHaveProperty('list');
    expect(addGroupRole(list, 'Staff', 'admin')).toEqual({ problem: 'duplicate' });
    const full = Array.from({ length: MAX_GROUP_ROLES }, (_, i) => ({ group: `g${i}`, role: 'member' as const }));
    expect(addGroupRole(full, 'one-more', 'member')).toEqual({ problem: 'tooMany' });
  });

  it('compares groups exactly: another case is another group', () => {
    expect(addGroupRole(list, 'staff', 'member')).toHaveProperty('list');
  });

  it('changes a role and removes a mapping', () => {
    expect(setGroupRole(list, 'Staff', 'admin')).toEqual([{ group: 'Staff', role: 'admin' }]);
    expect(removeGroupRole(list, 'Staff')).toEqual([]);
  });

  it('checks a whole list before it is sent', () => {
    expect(groupRolesValid(list)).toBe(true);
    expect(groupRolesValid([...list, { group: 'Staff', role: 'admin' }])).toBe(false);
    expect(groupRolesValid([{ group: '', role: 'member' }])).toBe(false);
  });

  it('treats the same mappings in another order as unchanged', () => {
    const a: SsoGroupRole[] = [
      { group: 'A', role: 'admin' },
      { group: 'B', role: 'member' },
    ];
    expect(sameGroupRoles(a, [...a].reverse())).toBe(true);
    expect(sameGroupRoles(a, [{ group: 'A', role: 'member' }, a[1] as SsoGroupRole])).toBe(false);
    expect(sameGroupRoles(a, a.slice(1))).toBe(false);
  });
});

describe('changedSsoFields: only what changed, the group list whole', () => {
  it('sends nothing when nothing changed', () => {
    expect(changedSsoFields(settings, formOf(settings))).toEqual({});
  });

  it('sends each changed field, and the whole group list when any mapping changed', () => {
    const form = formOf(settings);
    form.jit_provisioning = true;
    form.group_roles = [...form.group_roles, { group: 'Admins', role: 'admin' }];
    expect(changedSsoFields(settings, form)).toEqual({
      jit_provisioning: true,
      group_roles: [
        { group: 'Staff', role: 'member' },
        { group: 'Admins', role: 'admin' },
      ],
    });
  });

  it('sends an emptied list, which clears the mappings', () => {
    expect(changedSsoFields(settings, { ...formOf(settings), group_roles: [] })).toEqual({ group_roles: [] });
  });

  it('refuses a list that can\'t be sent', () => {
    const form = { ...formOf(settings), group_roles: [{ group: 'Staff', role: 'member' as const }, { group: 'Staff', role: 'admin' as const }] };
    expect(changedSsoFields(settings, form)).toBeNull();
  });

  it('does not share the settings\' list with the form', () => {
    const form = formOf(settings);
    form.group_roles[0]!.role = 'admin';
    expect(settings.group_roles[0]?.role).toBe('member');
  });
});

describe('ssoRequiredBlockers: an active connection and a confirmed MFA first', () => {
  it('names what is missing', () => {
    expect(ssoRequiredBlockers({ connection: null, sso_mfa_confirmed_at: null })).toEqual(['connection', 'mfa']);
    expect(
      ssoRequiredBlockers({ connection: { ...settings.connection!, status: 'inactive' }, sso_mfa_confirmed_at: '2026-11-01T00:00:00Z' }),
    ).toEqual(['connection']);
    expect(ssoRequiredBlockers({ connection: settings.connection, sso_mfa_confirmed_at: null })).toEqual(['mfa']);
    expect(ssoRequiredBlockers({ connection: settings.connection, sso_mfa_confirmed_at: '2026-11-01T00:00:00Z' })).toEqual([]);
  });
});

describe('the query cache after a domain call', () => {
  it('adds a new claim, replaces a verified one, and drops a removed one', () => {
    const added = withDomain(settings, domain('new.example'));
    expect(added.domains.map((entry) => entry.domain)).toEqual(['example.co.jp', 'new.example']);
    const verified = withDomain(added, domain('example.co.jp', { status: 'verified' }));
    expect(verified.domains[0]?.status).toBe('verified');
    expect(verified.domains).toHaveLength(2);
    expect(withoutDomain(verified, 'id-new.example').domains).toHaveLength(1);
  });
});

describe('verifyProblem', () => {
  it('explains a missing record and a domain proven elsewhere, and leaves other codes to the general text', () => {
    expect(verifyProblem('validation_failed')).toBe('unverified');
    expect(verifyProblem('invalid_state')).toBe('taken');
    expect(verifyProblem('not_found')).toBeNull();
    expect(verifyProblem(null)).toBeNull();
  });
});
