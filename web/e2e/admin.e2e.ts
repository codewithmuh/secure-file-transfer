import { expect, test, type Browser, type Page } from '@playwright/test';
import { fillKeycloak, mailTo, signIn, unique, USERS } from './support/stack';

/**
 * #197: an admin manages members and the tenant policy in the browser, against `make up` and `make seed`; an invited
 * member joins through the invitation the notification worker sends (Keycloak and Mailpit standing in for Cognito and
 * SES).
 */

function row(page: Page, email: string) {
  return page.getByRole('row').filter({ has: page.getByText(email, { exact: true }) });
}

async function menuAction(page: Page, email: string, action: string): Promise<void> {
  await page.getByRole('button', { name: `Actions for ${email}` }).click();
  await page.getByRole('menuitem', { name: action }).click();
}

async function confirm(page: Page, action: string): Promise<void> {
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: action }).click();
  await expect(dialog).toBeHidden();
}

/** The temporary password in an invitation email, English or Japanese. */
function temporaryPassword(text: string): string {
  const found = /(?:password|パスワード)[:：]\s*([A-Za-z0-9_-]{20,})/.exec(text);
  if (!found?.[1]) throw new Error('no temporary password in the invitation');
  return found[1];
}

/** A first sign-in with the temporary password: Keycloak, like Cognito, makes the member choose their own. */
async function join(browser: Browser, email: string, temporary: string): Promise<void> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/');
  await expect(page).toHaveURL(/\/sign-in$/);
  await page.getByRole('button', { name: 'Sign in with password or passkey' }).click();
  await fillKeycloak(page, email, temporary);
  await page.locator('#password-new').fill('local-only-new-member-password');
  await page.locator('#password-confirm').fill('local-only-new-member-password');
  await page.locator('[type="submit"]').click();
  await expect(page).toHaveURL('http://localhost:3000/');
  await expect(page.getByRole('banner').getByText(email)).toBeVisible();
  await context.close();
}

test('invite a member who joins, change the DLP approver, sign out, reset, deactivate', async ({ page, browser, request }) => {
  await signIn(page, 'admin', '/admin/users');
  const email = `${unique('e2e-invite')}@example.com`;

  // Invite: the row shows the user as invited.
  await page.getByRole('button', { name: 'Invite user' }).click();
  await page.getByRole('dialog').getByLabel('Email address').fill(email);
  await page.getByRole('dialog').getByRole('button', { name: 'Send invitation' }).click();
  await expect(row(page, email).getByText('Invited', { exact: true })).toBeVisible();

  // The same address again: 409 user_exists, explained in the dialog.
  await page.getByRole('button', { name: 'Invite user' }).click();
  await page.getByRole('dialog').getByLabel('Email address').fill(email);
  await page.getByRole('dialog').getByRole('button', { name: 'Send invitation' }).click();
  await expect(page.getByRole('dialog').getByText('This address is already a user of your organization.')).toBeVisible();
  await page.keyboard.press('Escape');

  // The invitation arrives in Mailpit with a temporary password; the first sign-in sets their own.
  const invitation = await mailTo(request, email);
  await join(browser, email, temporaryPassword(invitation.text));
  await page.reload();
  await expect(row(page, email).getByText('Active', { exact: true })).toBeVisible();

  // The seeded member becomes a DLP approver, and back.
  const member = USERS.member.email;
  await menuAction(page, member, 'Make DLP approver');
  await expect(row(page, member).getByRole('cell', { name: 'Yes', exact: true })).toBeVisible();
  await menuAction(page, member, 'Remove DLP approver');
  await expect(row(page, member).getByRole('cell', { name: 'Yes', exact: true })).toHaveCount(0);

  // Sign the new member out everywhere, then reset their sign-in: a new invitation arrives.
  await menuAction(page, email, 'Sign out everywhere');
  await confirm(page, 'Sign out everywhere');
  await menuAction(page, email, 'Reset sign-in');
  await confirm(page, 'Reset sign-in');
  await expect
    .poll(async () => temporaryPassword((await mailTo(request, email)).text), { timeout: 60_000 })
    .not.toBe(temporaryPassword(invitation.text));

  // Deactivate them.
  await menuAction(page, email, 'Deactivate');
  await expect(page.getByRole('dialog').getByText(email, { exact: false })).toBeVisible();
  await confirm(page, 'Deactivate');
  await expect(row(page, email).getByText('Deactivated', { exact: true })).toBeVisible();
});

test('resending an invitation, then deactivating an invited user who never joined', async ({ page, request }) => {
  await signIn(page, 'admin', '/admin/users');
  const email = `${unique('e2e-never')}@example.com`;
  await page.getByRole('button', { name: 'Invite user' }).click();
  await page.getByRole('dialog').getByLabel('Email address').fill(email);
  await page.getByRole('dialog').getByRole('button', { name: 'Send invitation' }).click();
  await expect(row(page, email).getByText('Invited', { exact: true })).toBeVisible();
  const first = temporaryPassword((await mailTo(request, email)).text);
  // "Resend invitation": a new temporary password arrives; the user stays invited.
  await menuAction(page, email, 'Resend invitation');
  await confirm(page, 'Resend invitation');
  await expect
    .poll(async () => temporaryPassword((await mailTo(request, email)).text), { timeout: 60_000 })
    .not.toBe(first);
  await expect(row(page, email).getByText('Invited', { exact: true })).toBeVisible();
  await menuAction(page, email, 'Deactivate');
  await confirm(page, 'Deactivate');
  await expect(row(page, email).getByText('Deactivated', { exact: true })).toBeVisible();
});

test('demoting the only admin is refused with last_admin explained', async ({ page }) => {
  await signIn(page, 'admin', '/admin/users');
  await page.getByLabel('Role').first().selectOption('admin');
  await page.getByLabel('Status').selectOption('active');
  // Once the filtered list is in: only admins are listed.
  await expect(page.getByRole('row').filter({ hasText: 'Member' })).toHaveCount(0);
  await expect(row(page, USERS.admin.email)).toBeVisible();
  const admins = page.getByRole('row').filter({ has: page.getByRole('button', { name: /^Actions for / }) });
  test.skip((await admins.count()) !== 1, 'another active admin exists in this tenant');
  await menuAction(page, USERS.admin.email, 'Make member');
  await page.getByRole('dialog').getByRole('button', { name: 'Make member' }).click();
  await expect(page.getByRole('dialog').getByText('Your organization needs at least one active admin.', { exact: false })).toBeVisible();
  await page.keyboard.press('Escape');
});

test('the policy cap reaches the member\'s form; unscannable files allowed and back', async ({ page, browser }) => {
  await signIn(page, 'admin', '/admin/policy');
  const maxExpiry = page.getByLabel('Maximum expiry');
  const save = page.getByRole('button', { name: 'Save' });
  const saved = () => page.waitForResponse((r) => r.url().endsWith('/v1/tenant/policy') && r.request().method() === 'PATCH');

  try {
    await maxExpiry.selectOption('P3D');
    let answer = saved();
    await save.click();
    const body = (await (await answer).request().postDataJSON()) as Record<string, unknown>;
    expect(body).toEqual({ max_expiry: 'P3D' }); // only what changed

    // The member's form now offers nothing longer than 3 days, and 3 days by default.
    const context = await browser.newContext();
    const member = await context.newPage();
    await signIn(member, 'member', '/transfers/new');
    const expiry = member.getByLabel('Expiry');
    await expect(expiry).toHaveValue('P3D');
    const offered = await expiry.locator('option').evaluateAll((options) => options.map((o) => (o as HTMLOptionElement).value));
    expect(offered).toEqual(['PT1H', 'PT6H', 'PT12H', 'P1D', 'P3D']);
    await context.close();

    // Unscannable files: allow with a warning, then block again.
    await page.getByLabel('Allow them, with a warning').check();
    answer = saved();
    await save.click();
    expect((await answer).status()).toBe(200);
    await page.getByLabel('Block them').check();
    answer = saved();
    await save.click();
    expect(((await answer).request().postDataJSON() as Record<string, unknown>).unscannable_policy).toBe('block');
  } finally {
    await maxExpiry.selectOption('P30D');
    const answer = saved();
    await save.click();
    await answer;
  }
});
