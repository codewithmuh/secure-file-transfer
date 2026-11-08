// No mock data or simulated delay in a routed page (#196). Walks the static imports from src/main.tsx, so it checks
// exactly the code the app can run, and fails on mock data or a timer standing in for the API. M5's pages stay in the
// repository unrouted (#195) and are not reached, so they aren't checked.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'src');

// The recipient's link page (/t) still fakes its session until #198 makes it live. Remove each entry with #198.
const PENDING = new Map([
  ['src/features/recipient/VerificationPage.tsx', '#198'],
  ['src/features/recipient/RecipientDownloadPage.tsx', '#198'],
]);

const MOCK = [
  [/\bmock[A-Z_]\w*/, 'mock data'],
  [/\/\/\s*Mock\b/, 'a mock'],
  // `await new Promise((resolve) => setTimeout(resolve, 1000))`: a timer standing in for a call.
  [/await new Promise\(\(?\s*resolve\s*\)?\s*=>\s*setTimeout\(\s*resolve\b/, 'a simulated delay'],
];

function resolveImport(from, specifier) {
  let base;
  if (specifier.startsWith('@/')) base = join(src, specifier.slice(2));
  else if (specifier.startsWith('.')) base = resolve(dirname(from), specifier);
  else return null; // a package
  for (const candidate of [base, `${base}.ts`, `${base}.tsx`, join(base, 'index.ts'), join(base, 'index.tsx')]) {
    if (existsSync(candidate) && /\.(ts|tsx)$/.test(candidate)) return candidate;
  }
  return null;
}

const seen = new Set();
const queue = [join(src, 'main.tsx')];
while (queue.length > 0) {
  const file = queue.pop();
  if (seen.has(file)) continue;
  seen.add(file);
  const code = readFileSync(file, 'utf8');
  for (const match of code.matchAll(/^\s*(?:import|export)\s+(?!type\b)(?:[^'";]*?\sfrom\s+)?['"]([^'"]+)['"]/gm)) {
    const target = resolveImport(file, match[1]);
    if (target) queue.push(target);
  }
}

const problems = [];
const pending = [];
for (const file of [...seen].sort()) {
  const name = relative(root, file);
  const code = readFileSync(file, 'utf8');
  for (const [pattern, what] of MOCK) {
    if (!pattern.test(code)) continue;
    if (PENDING.has(name)) pending.push(`${name} (${PENDING.get(name)})`);
    else problems.push(`${name}: ${what} in a routed page`);
    break;
  }
}

if (pending.length > 0) console.log(`Routed pages still pending their issue: ${[...new Set(pending)].join(', ')}`);
if (problems.length > 0) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`No mock data in the ${seen.size} files the app imports.`);
