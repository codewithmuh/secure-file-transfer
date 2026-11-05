# DLP detectors and text extraction

| | |
|---|---|
| Requirements | [PRD](../prd.md), FR-36 to FR-56, NFR-23 to NFR-26 |
| Decision | [ADR-0022](../adr/0022-dlp-inspection-engine.md): our own detectors, in sandboxed inspector pods beside the scan workers |
| Architecture | [architecture.md](../architecture.md), section 4.6 |
| Data model | [data-model.md](data-model.md), sections 2.7 and 3.5 |
| Tracking | [#64](https://github.com/codewithmuh/secure-file-transfer/issues/64) |

This page specifies what the DLP inspector extracts from a file, how text is normalised, each built-in detector and
how it is validated, what tenants can add, the default policy a new tenant starts with, how findings are masked, and
how accuracy is tested. Where ADR-0022 decides something, this page gives the detail; the ADR wins if they disagree.

No example on this page is a real identifier. Where a format needs showing, it is shown as a shape (`NNNN-NNNN-NNNN`),
never as a value that passes its check.

## 1. How a file is inspected

1. **Type from the bytes.** The inspector reads the first 64 KiB and decides the type from magic numbers and
   structure, never from the file name or the declared content type. An Office file is recognised as a zip with the
   right content-types part; a zip with an Office extension but no such part is an archive.
2. **Extraction** into text units, each with a location hint: a page, a sheet and row, a slide, a line, a paragraph, a
   document part (header, footer, comments, notes, properties) or an archive member path (section 2).
3. **Normalisation** of each unit (section 3).
4. **Detectors** run on each unit, with its context: nearby keywords, and for CSV and spreadsheets the column's
   header (section 4).
5. **Counting and masking.** Per detector the inspector counts distinct values at each confidence, keeps at most 10
   location hints and at most 3 masked previews (section 7), and returns them with the file's result and reasons.
   Matched values never leave the child process that found them (ADR-0022).

| Result | Meaning |
|---|---|
| `inspected` | All of the file's content was extracted within the limits and checked |
| `partial` | Some content was checked and some wasn't; the reasons say why. Findings so far count. |
| `not_inspected` | Nothing could be checked; the reasons say why |
| `failed` | The inspection kept failing with engine errors; the file is blocked and an operator alert fires (FR-47) |
| `skipped` | The file is `infected` or `scan_failed`, so it is blocked anyway; findings are discarded, never stored |

| Reason | When | Result |
|---|---|---|
| `encrypted` | A password-protected zip member, a PDF that needs a password to open, an encrypted Office file | `not_inspected` for the whole file, `partial` for one member of an archive |
| `no_text` | A PDF with no text layer, such as a scan; v1 has no OCR | `not_inspected`, or `partial` for some pages |
| `unsupported_type` | A type with no extractor: images, audio, video, CAD, executables, legacy Office binaries, RTF, 7z, RAR, LZH, email files | `not_inspected`, or `partial` for a member of an archive |
| `too_large` | Over 2,000,000,000 bytes: GuardDuty scans it and the scan worker never reads it (ADR-0019) | `not_inspected` |
| `limit_exceeded` | Past a limit of ADR-0022: nesting, members, decompressed bytes, ratio, extracted text, pages, CPU, time or memory | `partial` |
| `parse_error` | Malformed content an extractor can't read | `partial`, or `not_inspected` if nothing could be read |

Images inside an Office document or a PDF page that also has text are skipped without a reason: nearly every document
has a logo, and v1 inspects no images at all, which the PRD states (non-goals) and the threat model accepts (R-17).

## 2. Text extraction

| Format | Recognised by | Extracted | Location hint |
|---|---|---|---|
| Plain text, including JSON, XML, HTML and logs | Decodes as text (below) | The whole text, markup included | Line |
| CSV and TSV | Text with a consistent delimiter in the first lines | Every cell; the first non-empty row is the header | Row and column |
| Word processing (`.docx`, `.docm`, `.odt`) | Zip with the part list of the format | Body, tables, headers, footers, footnotes, endnotes, comments, text boxes, document properties | Paragraph; part |
| Spreadsheets (`.xlsx`, `.xlsm`, `.ods`) | As above | Cell values (shared strings and inline strings, formulas' cached results), sheet names, comments, document properties; the first non-empty row of each sheet is its header | Sheet and row |
| Presentations (`.pptx`, `.pptm`, `.odp`) | As above | Slide text, tables, notes, comments, document properties | Slide; part |
| PDF | `%PDF-` header | The text layer of each page, through PDFium | Page |
| Zip, gzip, tar | Their headers | Each member, recursively, as its own type | Member path, then the member's own hint |

**Encodings for text.** In this order: a byte order mark (UTF-8, UTF-16 LE or BE); strict UTF-8; ISO-2022-JP when its
escape sequences appear; strict CP932, which covers Shift_JIS; strict EUC-JP. Bytes that decode as none of these are
binary, so `unsupported_type`. Zip member names without the UTF-8 flag are read as CP932, which Japanese archivers use.

**Office files** are parsed part by part as XML, streamed, with DTDs, entities and network access off. Spreadsheets are
read in row order so each cell knows its column header. Embedded Office files and archives are members, and count
against the nesting limit.

## 3. Normalisation and matching

- **Unicode NFKC**, then case folding. Full-width digits and letters become ASCII, half-width katakana becomes
  full-width, and the ideographic space becomes a space, so a My Number typed in full-width digits matches like any
  other.
- **Separators in numbers.** Between digits, the dashes and minus signs that IMEs produce (hyphen-minus, hyphen,
  non-breaking hyphen, figure dash, en and em dash, minus sign, the katakana prolonged sound mark) count as a hyphen,
  and any run of spaces as one space. Each detector says which groupings it accepts.
- **Digit boundaries.** A number must not continue into another digit or ASCII letter on either side, so a 12-digit
  run inside a 20-digit one is not a My Number. Japanese text has no word boundaries, so numeric detectors use digit
  boundaries only and never require spaces around a number.
- **Line breaks.** Extractors join a cell, paragraph or page into one unit. For keyword matching, spaces and line
  breaks between two CJK characters are removed as well, because PDF text layers break Japanese words across lines.
- **Context.** A detector's context keywords count when they appear within 40 characters before or after the match, in
  the same unit, or in the header of the match's column in a CSV file or a sheet. Context keywords are listed in
  English and Japanese for every detector that uses them. An ASCII keyword counts only as a whole word: no ASCII letter
  right before it, and none right after it but a plural "s", so "tel" doesn't count in "hotel" or "cell" in
  "excellent". A digit may follow ("TEL03-…"). Japanese keywords count wherever they appear. The credential keywords
  are the exception: they also count inside identifiers such as `awsSecretAccessKey`.
- **Distinct values.** Within one file, a value found twice counts once. The inspector counts distinct values with a
  keyed hash whose key is random per file and lives only in the child process, so nothing that could be matched back to
  a value is ever stored. Across files and transfers, counts add up (FR-48), which overcounts a value that appears in
  two files; that errs on the side of the rule.
- **Confidence.** Every match is `low`, `medium` or `high` by its detector's rules (section 4), and counts at the
  highest level it reaches. A rule counts matches at or above its `min_confidence`.

## 4. Built-in detectors

Detector IDs are stable; the version of the whole set is the inspection engine version recorded on each file
(section 9).

| ID | Finds | Format and validation | Context keywords (examples) | Confidence |
|---|---|---|---|---|
| `jp_my_number` | Individual Numbers (マイナンバー, 個人番号) | 12 digits, plain or `NNNN-NNNN-NNNN` or with spaces; the check digit must hold (4.1) | マイナンバー, 個人番号, 番号カード, My Number, Individual Number | High with context; medium when grouped 4-4-4; low otherwise |
| `jp_corporate_number` | Corporate Numbers (法人番号) | 13 digits; the first digit is a check digit (4.2) | 法人番号, 会社法人等番号, Corporate Number | High with context; low otherwise |
| `payment_card` | Payment card numbers | 13 to 19 digits, plain or in the network's grouping; Luhn; a known issuer range and a length that range uses (4.3) | カード番号, クレジット, 有効期限, セキュリティコード, card number, expiry, CVV | High with context or an expiry date nearby; medium when grouped; low otherwise |
| `jp_bank_account` | Japanese bank accounts | A 7-digit account number with an account keyword; for Japan Post Bank a 5-digit symbol and an up to 8-digit number with its keywords. No check digit exists. | 口座番号, 普通, 当座, 預金, 支店, ゆうちょ, 記号, account number | Never without context. Medium with context. High with context and a valid bank and branch code pair within 80 characters or in the same row (4.4) |
| `iban` | International bank account numbers | ISO 13616: country code, two check digits, the country's length; mod 97 = 1 | IBAN, 口座, account | High with context or in groups of four; medium otherwise |
| `phone_number` | Japanese and international phone numbers | Validated with libphonenumber's metadata (the `phonenumbers` package): Japanese numbers without a country code, others with `+` and a country code (4.5) | 電話, TEL, 携帯, 連絡先, FAX, phone, mobile | High with context; medium when formatted with hyphens, parentheses or `+`; low when bare digits |
| `email_address` | Email addresses | A dot-atom local part, `@`, and a domain whose last label is in the bundled public suffix list | — | High: the format alone is unambiguous |
| `jp_passport` | Japanese passport numbers | Two letters and seven digits. No check digit exists. | 旅券, 旅券番号, パスポート, passport | Never without context. Medium with context |
| `passport_mrz` | Passport machine-readable zones, any country | ICAO 9303 TD3: two lines of 44 characters from `A–Z`, `0–9` and `<`; the check digits of the document number, birth date, expiry date and the composite must hold (4.6) | — | High |
| `jp_drivers_licence` | Japanese driver's licence numbers | 12 digits whose first two are a prefectural public safety commission code; the 11th is a check digit by the commonly documented rule (4.7) | 運転免許, 免許証番号, 免許番号, driver's licence, driver's license | Never without context. High with context and the check digit; medium with context only |
| `cloud_credential` | Cloud and service credentials | AWS access key IDs (a known four-letter prefix and 16 base32 characters) and secret access keys (40 characters, near a key ID or its keywords); Google Cloud service account key files; Azure storage connection strings with an account key; GitHub tokens with their checksums; this service's own API keys (`sft_` prefix and checksum). Patterns from a pinned, reviewed subset of the gitleaks rule set (MIT), which is written for RE2. | secret, key, token, credential, アクセスキー | High for checksummed tokens, key files and a key ID with its secret; medium for a key ID or a keyword-anchored secret alone |
| `private_key` | Private keys | PEM blocks whose label ends in `PRIVATE KEY`, encrypted PKCS #8 included; OpenSSH and PuTTY private key files; PGP private key blocks. The base64 body must decode. | — | High |
| `confidentiality_label` | Confidentiality marks | A built-in list: 社外秘, 部外秘, 関係者外秘, 極秘, 機密, 秘密, 取扱注意, Confidential, Strictly Confidential, Internal Use Only, Do Not Distribute | — | Medium when the mark stands alone in its line, cell, header, footer or a document property; low inside running text |

Names of people and postal addresses aren't detected in v1: in Japanese they need a named-entity model, and a pattern
for them would warn on almost every business document (non-goals).

### 4.1 My Number check digit

From the ordinance of the Ministry of Internal Affairs and Communications that defines it (総務省令第85号, article 5). Take
the first 11 digits. Let P(n) be the n-th of them counting from the right (n = 1 to 11), and Q(n) = n + 1 for n from 1
to 6 and n − 5 for n from 7 to 11. Let r be the sum of P(n) × Q(n), modulo 11. The check digit, the 12th digit, is 0
when r is 0 or 1, and 11 − r otherwise. A random 12-digit number passes about one time in ten, which is why the check
alone gives only low confidence: product codes (UPC-A has 12 digits) and order numbers pass too.

### 4.2 Corporate Number check digit

From the National Tax Agency's published method. The check digit is the **first** of the 13 digits; the other 12 are
the base number. Number the base digits from the right, n = 1 to 12. The check digit is 9 minus ((2 × the sum of the
even-numbered digits + the sum of the odd-numbered digits) modulo 9). Corporate Numbers are public: the National Tax
Agency publishes them with each company's name and address. The default policy only records them (section 6).

### 4.3 Payment cards

The Luhn check and these issuer ranges and lengths: 4 (13, 16 or 19 digits); 51–55 and 2221–2720 (16); 34 and 37
(15); 3528–3589 (16–19); 36, 300–305 and 38–39 (14–19); 6011, 644–649 and 65 (16–19); 62 (16–19). The ranges are data,
bundled and reviewed at each release. Accepted groupings: 4-4-4-4, 4-6-5, 4-6-4 and 4-4-4-4-3, with spaces or
hyphens. An expiry date (`MM/YY` or `MM/YYYY`, or 有効期限 with a date) within 40 characters raises a match to high.

### 4.4 Japanese bank accounts

There is no check digit, so this detector rests on context. An account number is 7 digits, often after 普通 or 当座.
Japan Post Bank accounts are written as a 5-digit symbol starting with 1 and a number of up to 8 digits, and count only
with their keywords; a number that runs on past 8 digits isn't one.

**High confidence.** A 7-digit account with its keywords is high when a valid bank code (4 digits) followed by a valid
branch code (3 digits) of that bank appears within 80 characters of it, before or after, or anywhere in the same row
of a spreadsheet or CSV file. Each code is a whole number, not part of a longer one; a pair that isn't on the list, or a
branch code before its bank code, leaves the account medium. Japan Post Bank accounts have no branch code and stay
medium.

The list is data: a sorted set of 7-digit codes (bank, then branch) with its source, licence and retrieval date in its
header, bundled with the detectors (`sft/dlp/detect/bank_codes.txt`) and read once per process. Japan's roughly
30,000 branches make about 240 KB on disk and 2 MB in memory, and parse in tens of milliseconds, inside the
inspector's start-up and memory budgets. `tools/bank_codes.py` writes it from a CSV the maintainer obtained under
terms that allow bundling; the service README gives the steps. It is refreshed before each release and at least every
three months, since banks merge and branches close; a stale list only leaves some accounts at medium.

**No list is bundled yet (#146).** No source whose licence allows redistribution has been confirmed: the Zengin-Net
data is distributed under contract, and the open lists found online (for example `zengin-code/source-data`, MIT for
the repository) are compiled from third-party sites whose own terms say nothing about reuse. Until one is, the
bundled file holds only its header, high is never reached, and a bank account is medium at most, which is the
confidence the default rule uses (section 6). The tests and the accuracy corpus use a synthetic list.

### 4.5 Phone numbers

Candidates are 10 or 11 digits starting with 0, or `+` and 8 to 15 digits, with optional hyphens, spaces, dots or
parentheses. A candidate counts only if libphonenumber says the number is valid: for Japan the area code, mobile
prefix (070, 080, 090), IP phone (050) or toll-free (0120, 0800) and the length must agree. Bare digits are low
confidence because invoice and order numbers have the same shape. Phone numbers matter in bulk, so the default rule
counts them with other personal data (section 6).

### 4.6 Passport machine-readable zones

ICAO Doc 9303: each check digit is the sum of the character values times the repeating weights 7, 3 and 1, modulo 10,
with `0–9` as themselves, `A–Z` as 10 to 35 and `<` as 0. Two consecutive 44-character lines that pass every check are
an MRZ, whatever the country; the preview keeps only the issuing country and the last 3 characters of the document
number.

### 4.7 Japanese driver's licences

A licence number has 12 digits: the issuing commission's code (2), the year of first issue (2), a serial (6), a check
digit (1) and the reissue count (1). The check digit isn't published by the National Police Agency. The rule that
public sources describe (the first 10 digits times 5, 4, 3, 2, 7, 6, 5, 4, 3, 2, summed, modulo 11; 11 minus that,
and 0 when the remainder is 0 or 1) is used only to raise a match to high, never to reject one. Without a context
keyword nothing is reported: the shape is the same as a My Number's.

## 5. Tenant detectors

A tenant admin adds up to 50 detectors of their own (FR-38, FR-39). Their definitions are encrypted with the tenant's
DLP data key, because keyword lists hold project names and other confidential terms
([encryption and keys](../security/encryption-and-keys.md) 3.3).

| Kind | Definition | Matching | Confidence | Limits |
|---|---|---|---|---|
| Keyword list (FR-38) | 1 to 1,000 terms of 1 to 100 characters | Normalised as in section 3. A term with any CJK character matches as a substring, with spaces and line breaks between CJK characters removed. A term of ASCII letters and digits matches as a whole word: no ASCII letter or digit right before or after it. | High | At most 50 detectors per tenant in total |
| Pattern (FR-39) | An RE2 expression of at most 512 characters; optional context keywords; optional minimum match length | On normalised text, case-insensitive if asked | High with context, low without, when context keywords are set; high otherwise | At most 20 patterns per tenant; compiled with an 8 MiB memory budget, every group non-capturing; refused if it doesn't compile, compiles to more than 1,000 RE2 instructions (forward or reverse), or matches the empty string, on its own or anywhere in the 1 MiB test text |

RE2 has no backreferences or lookaround, and runs in time linear in its input, so no pattern can make an inspection
slow without bound (threat model T-103). The save-time checks are deterministic: a pattern is accepted or refused the
same way on any machine. They bound the size of the program RE2 runs per character, not the time a pattern takes. Only
a match's span is used, so groups don't capture, and RE2 finds matches with its DFAs alone instead of the slower
submatch engines. A broad pattern can still make RE2's DFA rebuild its states often on some text: `(?:.{0,30}\d){1,2}q`
(548 instructions) takes about 2.5 s per MiB of random text. So each pattern also has a **scan-time budget per file**:

| Budget | Value | Why |
|---|---|---|
| CPU time | 0.5 s, plus 50 ms per MiB of text the pattern has scanned | About 20 times what an ordinary pattern costs per MiB; 20 patterns over a file's 256 MiB of text stay well inside the child's 10 minutes of CPU |
| Matches | 100,000 per file | Far above any rule's threshold; stops a pattern that matches nearly everything |

A pattern scans each unit in chunks of 64 KiB, and the budget is checked after each chunk, so a pattern stops at most
one chunk past it. A match may run up to 4 KiB past the chunk it starts in; a longer one is cut there. `^` and `$` keep
meaning the ends of the unit. Past its budget a pattern stops for the rest of the file: its matches so far still count,
the other detectors carry on, and the file's state doesn't change, since the outcome is the tenant admin's to fix, not
the sender's. The inspector's result names the stopped patterns by detector ID (`budget_exceeded`), never with a
match. The scan worker (DLP-4) writes one audit event per file, `dlp.pattern_budget_exceeded`, with the file and the
detector IDs, and the detector's admin view (`getDlpDetector`) shows how many files stopped it and when it last
happened; both arrive with those issues. The inspector's CPU and time limits (ADR-0022) still bound the whole file;
past them the file is `partial` with `limit_exceeded`. `testDlpDetectors` lets an admin try a detector on sample
text before saving it (FR-56).

## 6. The default policy

Every new tenant starts in enforce mode with this policy (FR-40). Every rule warns or records: nothing is held for
approval or blocked until a tenant admin has named approvers and chosen to (FR-43). Every match is recorded whatever
the rule does.

| Rule | Condition | Recipients | Action |
|---|---|---|---|
| Credentials and private keys | `cloud_credential`, `private_key`: 1 or more at medium | Any | Warn |
| My Numbers | `jp_my_number`: 1 or more at high | Any | Warn |
| Payment cards | `payment_card`: 1 or more at high | Any | Warn |
| Personal data in bulk | `phone_number`, `email_address`, `jp_bank_account`, `iban`, `jp_passport`, `passport_mrz`, `jp_drivers_licence`: 50 or more at medium, together | Any | Warn |
| Files that couldn't be fully inspected | Not fully inspected: `encrypted`, `too_large`, `limit_exceeded`, `parse_error` | Any | Warn |
| Images and files without text | Not fully inspected: `unsupported_type`, `no_text` | Any | Allow and record |
| Corporate Numbers and confidentiality labels | `jp_corporate_number`, `confidentiality_label`: 1 or more at medium | Any | Allow and record |
| New recipient domain (FR-46) | A recipient domain this tenant hasn't sent to in 365 days | Any | Warn |

A typical tightening, once approvers exist: My Numbers to any untrusted recipient need approval; credentials and
private keys to untrusted recipients are blocked; personal data in bulk needs approval above 500.

## 7. Masking and location hints

Findings never hold a matched value (FR-53, NFR-26). Each finding keeps at most 3 previews of at most 64 characters,
masked like this:

| Detector | Preview keeps |
|---|---|
| `jp_my_number` | Nothing of the number: "12 digits, check digit valid" |
| `jp_corporate_number` | The last 4 digits |
| `payment_card` | The card network and the last 4 digits |
| `jp_bank_account`, `jp_passport`, `jp_drivers_licence`, `passport_mrz` | The last 3 characters (and the issuing country for an MRZ) |
| `iban` | The country code and the last 4 characters |
| `phone_number` | The country code and the last 4 digits |
| `email_address` | The first character of the local part and the domain |
| `cloud_credential`, `private_key` | Nothing of the value: its kind only, such as "AWS access key ID" or "OpenSSH private key" |
| `confidentiality_label`, tenant keyword | The term that matched: it is the tenant's own list |
| Tenant pattern | The last 4 characters |

Location hints point to where a match is, never what is around it: page 12; sheet "顧客一覧", row 340; slide 4; line
88; `contracts/2026/appendix.xlsx`, sheet 2, row 9; header; document properties. A sheet name or an archive member path
can be as revealing as a file name, so hints and previews are stored together, encrypted with the tenant's DLP data key,
and deleted with the file's contents (data model 2.7).

## 8. Accuracy testing (NFR-25)

**The corpus is synthetic and generated, never collected.** A generator in the test suite builds the labelled corpus
from a fixed seed when the tests run. Nothing of it is committed, so no fake private key or access key is ever in git
for gitleaks and the private-key hook to find, and no list of check-valid identifiers is published. Generated values
are random and attached to no person; names, addresses and companies in the surrounding text come from fixed lists of
obviously fictional entries. The generator also writes the expected findings for each document: detector, location
and confidence.

| Part | What it holds |
|---|---|
| Positives | For each built-in detector: values that pass their checks, plain, grouped, in full-width digits and with IME dashes; with and without context keywords; in running text and in spreadsheet columns under a header; in English and Japanese text |
| Hard negatives | The same shapes with a wrong check digit; JAN, EAN-13 and UPC codes; order, invoice and serial numbers; dates and times; postal codes; version strings and IP addresses; digit runs longer than the detector's length; Luhn failures in card ranges; hashes, UUIDs and base64 blobs near the word "key"; ordinary text that contains 機密 or "confidential" as part of other words |
| Keywords | Tenant terms in English and Japanese, matched in full-width and half-width forms, upper and lower case, and split by a line break between CJK characters; ASCII terms inside longer words that must not match |
| Formats | Every positive and negative set rendered as UTF-8 text with and without a byte order mark, CP932 text, EUC-JP text, CSV in UTF-8 and CP932, `.xlsx`, `.docx`, `.pptx`, OpenDocument, PDF with a text layer, and zips nested 1 to 3 deep |
| Reasons | One fixture per reason and limit: an encrypted zip member, an encrypted PDF, an image-only PDF, a PNG, a 7z file, nesting 4 deep, 10,001 members, a 101:1 member, a decompression bomb, an XML entity bomb, a PDF of 5,001 pages, text past 256 MiB, a child that runs past its CPU and time limits |

**Measured per detector, format and confidence.** Precision is true matches over reported matches; recall is true
matches over the labelled positives at that confidence or above, counted by distinct value per document.

| Class | Detectors, at the confidence the default rules use | Precision | Recall |
|---|---|---|---|
| Check-digit identifiers | `jp_my_number` (high), `jp_corporate_number` (high), `payment_card` (high), `iban` (medium), `passport_mrz` (high) | ≥ 0.99 | ≥ 0.99 |
| Secrets | `cloud_credential` (medium), `private_key` (high), for the listed formats | ≥ 0.99 | ≥ 0.99 |
| Formatted identifiers | `phone_number` (medium), `email_address` (high) | ≥ 0.97 | ≥ 0.95 |
| Context identifiers | `jp_bank_account`, `jp_passport`, `jp_drivers_licence` (medium) | ≥ 0.90 | ≥ 0.90 |
| Keywords and labels | Tenant keyword lists, `confidentiality_label` (medium) | 1.00 | 1.00 across the listed forms |

At low confidence, check-digit identifiers must reach a recall of at least 0.99; their precision there isn't a
target, which is why the default rules don't use low. A bank account's high rule (4.4) is measured on its own, on the corpus's synthetic
code list: at least 0.90 precision and recall at high.

**In CI.** A pull request that touches the detector package or the extraction code runs a corpus of about 20,000
documents and fails if any detector, in any format, drops below its target, or if any reason fixture gives the wrong
result. A nightly job runs about 200,000 documents and the Atheris fuzzing of the extraction entry points (ADR-0022).
Test output names detectors, documents and counts, never a value, and the canary test (threat model section 6) runs
over the same flows. Each release publishes the per-detector table in its release notes.

## 9. Versions

The inspection engine version changes with any change to a built-in detector, its data (issuer ranges, public
suffixes, credential patterns, the bank code list, whose retrieval date is part of the version) or the extraction
code. Each file records the version that inspected it, and each
release's notes list what changed and the corpus results. A tenant's own detectors are versioned by the DLP policy
version (data model 2.7). Files aren't re-inspected when either changes (ADR-0022).

## 10. Not in v1

- OCR of images and of PDFs with no text layer; text inside images embedded in documents.
- Legacy binary Office files (`.doc`, `.xls`, `.ppt`), RTF, 7z, RAR and LZH archives, and email files with their
  attachments.
- Names of people, postal addresses and other data that needs a named-entity model or a classifier.
- Exact data matching (fingerprints of a tenant's own customer list) and document fingerprinting.
- Inspection of upload-request messages, which go from a member to the one uploader the member chose.

Each of these is a later issue. Until then a file in one of these formats gets its reason (section 1), and the
tenant's rules decide what happens to it.
