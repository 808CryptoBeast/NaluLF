// Discovers every tests/*.test.mjs file, runs each as its own subprocess
// (isolates global state and process.exitCode between suites), rebuilds
// the app first since tests run against www/, prints a combined summary,
// and exits non-zero if anything failed.
import { readdirSync } from 'fs';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

console.log('Building app before running tests...');
const build = spawnSync('npm', ['run', 'build'], { cwd: ROOT, stdio: 'inherit', shell: true });
if (build.status !== 0) {
  console.error('\nBuild failed — aborting test run.');
  process.exit(1);
}

const testFiles = readdirSync(__dirname)
  .filter((f) => f.endsWith('.test.mjs'))
  .sort();

if (!testFiles.length) {
  console.error('No *.test.mjs files found in tests/.');
  process.exit(1);
}

console.log(`\nRunning ${testFiles.length} test suite(s): ${testFiles.join(', ')}\n`);
console.log('='.repeat(60));

let anyFailed = false;
const results = [];
for (const file of testFiles) {
  const res = spawnSync('node', [path.join(__dirname, file)], { cwd: ROOT, stdio: 'inherit' });
  const failed = res.status !== 0;
  if (failed) anyFailed = true;
  results.push({ file, failed });
}

console.log('\n' + '='.repeat(60));
console.log('Summary:');
for (const { file, failed } of results) {
  console.log(`  ${failed ? '✗ FAILED' : '✓ passed'}  ${file}`);
}
console.log('='.repeat(60));

if (anyFailed) {
  console.error('\nOne or more test suites failed.');
  process.exit(1);
} else {
  console.log('\nAll test suites passed.');
  process.exit(0);
}
