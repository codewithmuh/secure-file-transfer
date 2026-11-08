/**
 * The web app's view of the API contract (FR-31). `schema.ts` is generated (`npm run gen:api`); this file names the
 * schemas the pages use, so they read `Transfer` rather than `components['schemas']['Transfer']`.
 */
import type { Schema } from './client';

export { api } from './client';
export type { ApiPath, ApiPaths, HttpMethod, Operation, PathsWith, RequestOptions, ResponseBody, Schema } from './client';

export type ActorType = Schema<'ActorType'>;
export type ApiKey = Schema<'ApiKey'>;
export type ApiKeyScope = Schema<'ApiKeyScope'>;
export type ApprovalDecision = Schema<'ApprovalDecision'>;
export type ApprovalRequest = Schema<'ApprovalRequest'>;
export type ApprovalRequestSummary = Schema<'ApprovalRequestSummary'>;
export type ApprovalState = Schema<'ApprovalState'>;
export type AuditEvent = Schema<'AuditEvent'>;
export type CurrentMember = Schema<'CurrentMember'>;
export type DlpAction = Schema<'DlpAction'>;
export type DlpConfidence = Schema<'DlpConfidence'>;
export type DlpDecision = Schema<'DlpDecision'>;
export type DlpDetector = Schema<'DlpDetector'>;
export type DlpFinding = Schema<'DlpFinding'>;
export type DlpMatchedRule = Schema<'DlpMatchedRule'>;
export type DlpOutcome = Schema<'DlpOutcome'>;
export type DlpPolicy = Schema<'DlpPolicy'>;
export type DlpRecipientCheck = Schema<'DlpRecipientCheck'>;
export type DlpRule = Schema<'DlpRule'>;
export type DlpRuleCondition = Schema<'DlpRuleCondition'>;
export type FileState = Schema<'FileState'>;
export type InspectionReason = Schema<'InspectionReason'>;
export type Problem = Schema<'Problem'>;
export type TenantPolicy = Schema<'TenantPolicy'>;
export type Transfer = Schema<'Transfer'>;
export type TransferDlp = Schema<'TransferDlp'>;
export type TransferState = Schema<'TransferState'>;
export type TransferSummary = Schema<'TransferSummary'>;
export type UploadRequest = Schema<'UploadRequest'>;
export type UploadRequestState = Schema<'UploadRequestState'>;
export type User = Schema<'User'>;
export type UserStatus = Schema<'UserStatus'>;
