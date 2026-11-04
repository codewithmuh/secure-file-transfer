/** Transfer status values per the OpenAPI contract. */
export type TransferStatus = 'draft' | 'sent' | 'held' | 'expired' | 'revoked' | 'cancelled';

/** File scan state per FR-16. */
export type FileScanState = 'uploading' | 'completing' | 'scanning' | 'clean' | 'infected' | 'unscannable' | 'scan_failed' | 'rejected';

export interface Transfer {
  id: string;
  status: TransferStatus;
  message: string | null;
  expires_in: string | null;
  expires_at: string | null;
  submitted_at: string | null;
  download_limit: number | null;
  notify_on_first_download: boolean;
  file_count: number;
  total_size: number;
  recipient_count: number;
  created_at: string;
  updated_at: string;
}

export interface TransferRecipient {
  id: string;
  email: string;
  locale: 'en' | 'ja';
  delivery_state: 'pending' | 'notified' | 'verified' | 'downloaded' | 'locked';
  notified_at: string | null;
  verified_at: string | null;
  first_downloaded_at: string | null;
}

export interface TransferFile {
  id: string;
  name: string;
  size: number;
  scan_state: FileScanState;
  warning: string | null;
  created_at: string;
}

export interface UploadRequest {
  id: string;
  email: string;
  locale: 'en' | 'ja';
  status: 'active' | 'expired' | 'revoked';
  message: string | null;
  expires_at: string;
  file_count: number;
  total_size: number;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  action: string;
  actor_type: 'member' | 'admin' | 'recipient' | 'uploader' | 'system' | 'operator';
  actor_email: string | null;
  target_type: string | null;
  target_id: string | null;
  ip_address: string;
  user_agent: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface TenantUser {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'member';
  status: 'active' | 'deactivated';
  last_sign_in_at: string | null;
  created_at: string;
}

export interface TenantPolicy {
  max_expiry_hours: number;
  allow_unscannable: boolean;
  received_file_retention_days: number;
  default_locale: 'en' | 'ja';
  allowed_domains: string[];
  blocked_domains: string[];
}

export interface ApiKey {
  id: string;
  prefix: string;
  name: string;
  scopes: string[];
  expires_at: string;
  last_used_at: string | null;
  created_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  next_cursor: string | null;
}
