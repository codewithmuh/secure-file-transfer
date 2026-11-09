// The design-load file mix ([CAP] 3.5, A4, A9, A38, A45, A46), drawn per file.
//
// Sizes, log-uniform within each band, so the mean is about 36 MB and the median about 3 MB (the PRD's median is 5 MB;
// A4's mean 33 MB, A9's "8 % of files and 70 % of bytes over 100 MB" and A38's 0.1 % over 2 GB are what the bands
// keep):
//
//   | Band              | Files  |
//   |-------------------|--------|
//   | up to 1 MB        | 25 %   |
//   | 1 to 10 MB        | 50 %   |
//   | 10 to 100 MB      | 17 %   |
//   | 100 to 500 MB     | 7.4 %  |
//   | 500 MB to 2 GB    | 0.5 %  |
//   | 2 to 5 GB         | 0.1 %  |
//
// Types: text-bearing files (DLP reads all of them) are 42 % of files up to 100 MB and 20 % above, so about 40 % of
// files and 25 % of bytes (A45); the rest are binary, which the inspector stops reading after 64 KiB. A quarter of the
// text files carry a synthetic My Number (A46), made at run time with a valid check digit and never stored anywhere.
//
// Bytes are sampled ([PRD] 6.1, [CAP] A42): with `bytesSample` below 1, each file keeps its drawn size with that
// probability and is otherwise `smallFileBytes`, so the API sees every call at full rate while only a share of the
// bytes moves. `maxFileBytes` caps the draw for a laptop.
import { randomBytes } from 'k6/crypto';

const MB = 1000 * 1000;
const PART = 5 * 1024 * 1024; // the API's part size for every file up to 5 GB (sft.service.uploads)
const BANDS = [
  [0.25, 1e3, 1 * MB],
  [0.5, 1 * MB, 10 * MB],
  [0.17, 10 * MB, 100 * MB],
  [0.074, 100 * MB, 500 * MB],
  [0.005, 500 * MB, 2000 * MB],
  [0.001, 2000 * MB, 5000 * MB],
];
const WORDS = ['report', 'review', 'quarterly', 'budget', 'meeting', 'draft', 'final', 'schedule', 'project', 'summary'];

function logUniform(low, high) {
  return Math.round(Math.exp(Math.log(low) + Math.random() * (Math.log(high) - Math.log(low))));
}

export function drawSize() {
  let roll = Math.random();
  for (const [share, low, high] of BANDS) {
    if (roll < share) return logUniform(low, high);
    roll -= share;
  }
  return logUniform(1e3, 1 * MB);
}

/** A synthetic My Number: 11 random digits and the check digit of the DLP corpus's rule. */
export function myNumber() {
  const digits = Array.from({ length: 11 }, () => Math.floor(Math.random() * 10));
  let sum = 0;
  for (let i = 0; i < 11; i += 1) {
    const n = i + 1;
    sum += digits[10 - i] * (n <= 6 ? n + 1 : n - 5);
  }
  const rest = sum % 11;
  return digits.join('') + String(rest <= 1 ? 0 : 11 - rest);
}

/** Per VU, made once: one part of plain words and one of random bytes, sliced for each part. */
let textPart = null;
let binaryPart = null;

function parts() {
  if (textPart === null) {
    const lines = [];
    let length = 0;
    while (length < PART) {
      const line = `${Array.from({ length: 12 }, () => WORDS[Math.floor(Math.random() * WORDS.length)]).join(' ')}\n`;
      lines.push(line);
      length += line.length;
    }
    textPart = lines.join('').slice(0, PART);
    binaryPart = randomBytes(PART);
  }
  return { textPart, binaryPart };
}

/** One file of the mix under `profile`: its name, type, size and a function giving part n's bytes. */
export function drawFile(profile) {
  const drawn = Math.min(drawSize(), profile.maxFileBytes);
  const text = Math.random() < (drawn <= 100 * MB ? 0.42 : 0.2);
  const size = Math.random() < profile.bytesSample ? drawn : profile.smallFileBytes;
  // NFR-5's class follows the bytes that actually move.
  const sizeClass = size <= 100 * MB ? 'small' : 'large';
  const marked = text && Math.random() < 0.25;
  const prefix = marked ? `Individual Number: ${myNumber()}\n` : '';
  return {
    name: `lt-${Math.random().toString(36).slice(2, 10)}.${text ? 'txt' : 'bin'}`,
    contentType: text ? 'text/plain' : 'application/octet-stream',
    size,
    sizeClass,
    body(partNumber, partSize) {
      const { textPart: t, binaryPart: b } = parts();
      const start = (partNumber - 1) * partSize;
      const length = Math.min(partSize, size - start);
      if (!text) return b.slice(0, length);
      const chunk = t.slice(0, length);
      return partNumber === 1 && prefix ? prefix + chunk.slice(prefix.length) : chunk;
    },
  };
}
