/** The owner's address when the admin's user list has it (`useUserEmails`), else the start of their ID (#217). */
export function ownerLabel(emails: ReadonlyMap<string, string> | undefined, userId: string): string {
  return emails?.get(userId) ?? `${userId.slice(0, 8)}…`;
}
