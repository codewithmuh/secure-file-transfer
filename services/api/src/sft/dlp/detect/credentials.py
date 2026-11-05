"""`cloud_credential`: cloud and service credentials ([DLP] 4).

The patterns follow the gitleaks rules for the same formats (MIT, written for RE2), reviewed and
narrowed:

- AWS access key IDs: a known four-letter prefix and 16 base32 characters. Medium alone; high with a
  secret access key within 200 characters, in the same unit or the next few (a credentials file puts
  them on two lines).
- AWS secret access keys: 40 base64 characters with upper case, lower case and a digit, anchored by
  a secret-key keyword within 40 characters, or within 200 characters of a key ID. A hex hash has
  one case only, so it never passes. A key ID with its secret counts as one credential.
- GitHub tokens: `ghp_`, `gho_`, `ghu_`, `ghs_` and `ghr_` with their CRC-32 checksum (high); a
  token whose checksum fails isn't one. Fine-grained `github_pat_` tokens have no published
  checksum: medium.
- This service's API keys: `sft_<env>_<secret>_<check>`, with the CRC-32 checksum of authentication
  and authorization 5.1 (high).
- Azure storage connection strings with an account key that decodes to 64 bytes (high).
- Google Cloud service account key files: `"type": "service_account"` and a `"private_key_id"`
  within the same few units (high). The private key inside is `private_key`'s, and the client email
  `email_address`'s.

A finding's preview is the credential's kind, never any of its characters (section 7).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator

from sft.dlp.detect import checks
from sft.dlp.detect.prepared import HIGH, MEDIUM, Hit, Keywords, Prepared
from sft.dlp.detect.regex import Regex

CLOUD_CREDENTIAL = "cloud_credential"

_AWS_KEY_ID = Regex(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}")
_AWS_SECRET = Regex(r"[A-Za-z0-9/+]{40}")
_AWS_SECRET_CONTEXT = Keywords(
    (
        *("aws_secret_access_key", "secret_access_key", "secretaccesskey", "aws_secret"),
        *("secret access key", "シークレットアクセスキー", "シークレットキー"),
    )
)
_GITHUB = Regex(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}")
_GITHUB_PAT = Regex(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}")
_SFT_KEY = Regex(r"sft_(?:dev|stg|prd)_[A-Za-z0-9]{43}_[A-Za-z0-9]{6}")
_AZURE = Regex(r"AccountName=([A-Za-z0-9]{3,24});AccountKey=([A-Za-z0-9+/]{86}==)")
_GCP_TYPE = Regex(r'"type"\s*:\s*"service_account"')
_GCP_KEY_ID = Regex(r'"private_key_id"\s*:\s*"([0-9a-f]{40})"')

_PAIR_DISTANCE = 200
"""A key ID and a secret within this many characters in one unit are a pair."""
_RECENT_UNITS = 3
"""A key ID seen this many units back still pairs with a secret; a GCP key file's fields, 30 units.
"""
_GCP_UNITS = 30
_PAIR = "AWS access key ID with its secret"

_WORD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_BASE64 = _WORD | frozenset("+/")
_BASE64_PADDED = _BASE64 | frozenset("=")


def _bounded(text: str, start: int, end: int, inside: frozenset[str]) -> bool:
    return (start == 0 or text[start - 1] not in inside) and (
        end == len(text) or text[end] not in inside
    )


def _mixed(secret: str) -> bool:
    return (
        any(c.isupper() for c in secret)
        and any(c.islower() for c in secret)
        and any(c.isdigit() for c in secret)
    )


class CredentialDetector:
    """Holds what can pair across units: recent AWS key IDs and secrets, and GCP key file fields."""

    def __init__(self) -> None:
        # (unit number, key ID, location)
        self._key_ids: deque[tuple[int, str, str]] = deque(maxlen=16)
        self._gcp_type: tuple[int, str] | None = None
        self._gcp_ids: deque[tuple[int, str, str]] = deque(maxlen=16)

    def feed(self, unit: Prepared, number: int) -> Iterator[tuple[Hit, str]]:
        text = unit.text
        yield from ((hit, unit.location) for hit in self._tokens(text))
        yield from self._aws(unit, number)
        yield from self._gcp(unit, number)

    def _tokens(self, text: str) -> Iterator[Hit]:
        for span in _GITHUB.finditer(text):
            if not _bounded(text, span.start, span.end, _WORD):
                continue
            token = text[span.start : span.end]
            body = token[4:]
            if checks.crc32_base62(body[:30]) == body[30:]:
                yield Hit(CLOUD_CREDENTIAL, HIGH, token, "GitHub token")
        for span in _GITHUB_PAT.finditer(text):
            if _bounded(text, span.start, span.end, _WORD):
                token = text[span.start : span.end]
                yield Hit(CLOUD_CREDENTIAL, MEDIUM, token, "GitHub fine-grained token")
        for span in _SFT_KEY.finditer(text):
            if not _bounded(text, span.start, span.end, _WORD):
                continue
            key = text[span.start : span.end]
            if checks.crc32_base62(key[:-7]) == key[-6:]:
                yield Hit(CLOUD_CREDENTIAL, HIGH, key, "secure-file-transfer API key")
        for span in _AZURE.finditer(text):
            account, account_key = span.groups
            if account is None or account_key is None:
                continue
            decoded = checks.decode_base64(account_key)
            if decoded is not None and len(decoded) == 64:
                value = account.lower() + ";" + account_key
                yield Hit(CLOUD_CREDENTIAL, HIGH, value, "Azure storage connection string")

    def _aws(self, unit: Prepared, number: int) -> Iterator[tuple[Hit, str]]:
        text = unit.text
        ids = [
            (span.start, text[span.start : span.end])
            for span in _AWS_KEY_ID.finditer(text)
            if _bounded(text, span.start, span.end, _WORD)
        ]
        # Candidate secrets: (start, anchored by a secret-key keyword).
        secrets: list[tuple[int, bool]] = []
        for span in _AWS_SECRET.finditer(text):
            secret = text[span.start : span.end]
            if (
                (span.start == 0 or text[span.start - 1] not in _BASE64)
                and (span.end == len(text) or text[span.end] not in _BASE64_PADDED)
                and _mixed(secret)
            ):
                anchored = unit.has_context(span.start, span.end, _AWS_SECRET_CONTEXT)
                secrets.append((span.start, anchored))
        paired: set[int] = set()
        for start, key_id in ids:
            near = [s for s, _ in secrets if abs(s - start) <= _PAIR_DISTANCE]
            paired.update(near)
            if near:
                yield Hit(CLOUD_CREDENTIAL, HIGH, key_id, _PAIR), unit.location
            else:
                yield Hit(CLOUD_CREDENTIAL, MEDIUM, key_id, "AWS access key ID"), unit.location
        # A key ID a few units back pairs with an anchored secret here: a credentials file's two
        # lines.
        recent = [entry for entry in self._key_ids if number - entry[0] <= _RECENT_UNITS]
        for start, anchored in secrets:
            if start in paired or not anchored:
                continue
            if recent:
                _, key_id, location = recent[-1]
                yield Hit(CLOUD_CREDENTIAL, HIGH, key_id, _PAIR), location
            else:
                secret = text[start : start + 40]
                yield Hit(CLOUD_CREDENTIAL, MEDIUM, secret, "AWS secret access key"), unit.location
        for _, key_id in ids:
            self._key_ids.append((number, key_id, unit.location))

    def _gcp(self, unit: Prepared, number: int) -> Iterator[tuple[Hit, str]]:
        text = unit.text
        if _GCP_TYPE.search(text) is not None:
            self._gcp_type = (number, unit.location)
            for seen, key_id, location in self._gcp_ids:
                if number - seen <= _GCP_UNITS:
                    yield (
                        Hit(CLOUD_CREDENTIAL, HIGH, key_id, "Google Cloud service account key"),
                        location,
                    )
            self._gcp_ids.clear()
        for span in _GCP_KEY_ID.finditer(text):
            found = span.groups[0]
            if found is None:
                continue
            key_id = found
            if self._gcp_type is not None and number - self._gcp_type[0] <= _GCP_UNITS:
                yield (
                    Hit(CLOUD_CREDENTIAL, HIGH, key_id, "Google Cloud service account key"),
                    unit.location,
                )
            else:
                self._gcp_ids.append((number, key_id, unit.location))
