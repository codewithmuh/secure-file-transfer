/**
 * The web app's view of the API contract (FR-31). `schema.ts` is generated (`npm run gen:api`); this file names the
 * schemas the pages use, so they read `Transfer` rather than `components['schemas']['Transfer']`.
 */
import type { Schema } from './client';

export { api } from './client';
export type { ApiPath, ApiPaths, HttpMethod, Operation, PathsWith, RequestOptions, ResponseBody, Schema } from './client';

export type ApiKey = Schema<'ApiKey'>;
export type ApiKeyScope = Schema<'ApiKeyScope'>;
export type AuditEvent = Schema<'AuditEvent'>;
export type CurrentMember = Schema<'CurrentMember'>;
export type FileState = Schema<'FileState'>;
export type Problem = Schema<'Problem'>;
export type TenantPolicy = Schema<'TenantPolicy'>;
export type Transfer = Schema<'Transfer'>;
export type TransferState = Schema<'TransferState'>;
export type TransferSummary = Schema<'TransferSummary'>;
export type UploadRequest = Schema<'UploadRequest'>;
export type UploadRequestState = Schema<'UploadRequestState'>;
export type User = Schema<'User'>;
export type UserStatus = Schema<'UserStatus'>;
