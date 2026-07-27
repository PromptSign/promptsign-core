// Keep every platform package and optionalDependency pin in lockstep with the
// main package version. Run before tagging a release:
//   npm version <x> && npm run sync-versions
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const writeJson = (p, o) => writeFileSync(p, JSON.stringify(o, null, 2) + '\n');

const mainPath = path.join(root, 'package.json');
const main = readJson(mainPath);
const version = main.version;

// 1. every npm/<platform>/package.json → main version
const npmDir = path.join(root, 'npm');
const platforms = readdirSync(npmDir, { withFileTypes: true }).filter((d) => d.isDirectory());
for (const d of platforms) {
  const pkgPath = path.join(npmDir, d.name, 'package.json');
  const pkg = readJson(pkgPath);
  pkg.version = version;
  writeJson(pkgPath, pkg);
  console.log(`${pkg.name} -> ${version}`);
}

// 2. main optionalDependencies pins → main version
if (main.optionalDependencies) {
  for (const dep of Object.keys(main.optionalDependencies)) {
    main.optionalDependencies[dep] = version;
  }
  writeJson(mainPath, main);
  console.log(`optionalDependencies pinned to ${version}`);
}
