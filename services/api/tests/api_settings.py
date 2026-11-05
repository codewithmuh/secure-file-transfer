"""The settings every public API `Settings` needs beyond its database: local, obviously fake values.

Member sign-in (#113), the counter store, the email-hmac keyring (#145) and the files buckets
(#114). Secrets and the buckets keep no defaults in `Settings`, so a test that builds one passes
these.
"""

import base64

CSRF_KEY = base64.b64encode(b"test-only-csrf-key-not-a-secret!").decode()
CSRF_KEYRING = f'[{{"id":"k1","state":"active","key":"{CSRF_KEY}"}}]'
EMAIL_KEY = base64.b64encode(b"test-only-email-key-not-secret!!").decode()
EMAIL_HMAC_KEYRING = (
    f'[{{"id":"t1","state":"active","key":"{EMAIL_KEY}","activated_at":"2026-01-01T00:00:00Z"}}]'
)
WEB_ORIGIN = "https://app.sft.test"
ISSUER = "https://idp.sft.test/realms/sft"
VALKEY_URL = "redis://u:p@127.0.0.1:1/0"

API_ENV: dict[str, str] = {
    "VALKEY_URL": VALKEY_URL,
    "WEB_ORIGIN": WEB_ORIGIN,
    "OIDC_ISSUER": ISSUER,
    "OIDC_CLIENT_ID": "sft-api-test",
    "OIDC_CLIENT_SECRET": "test-only-client-secret",
    "OIDC_REDIRECT_URI": "https://api.sft.test/v1/auth/callback",
    "OIDC_LOGOUT_URL": f"{ISSUER}/protocol/openid-connect/logout",
    "OIDC_PROVIDER_NAME": "local-keycloak",
    "CSRF_KEYRING": CSRF_KEYRING,
    "EMAIL_HMAC_KEYRING": EMAIL_HMAC_KEYRING,
    "S3_FILES_BUCKET": "sft-test-files",
    "S3_LARGE_FILES_BUCKET": "sft-test-large-files",
    "S3_FILES_KMS_KEY_ID": "alias/sft-test-files",
}
"""As environment variables, for tests that read the environment."""

API_SETTINGS: dict[str, str] = {name.lower(): value for name, value in API_ENV.items()}
"""As `Settings(**API_SETTINGS, ...)` keyword arguments."""
