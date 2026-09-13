#!/usr/bin/env node
'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const output = execFileSync('npm', ['sbom', '--sbom-format=cyclonedx'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'inherit'],
});
const parsed = JSON.parse(output);
if (parsed.bomFormat !== 'CycloneDX') throw new Error('npm returned an unexpected SBOM format');
fs.writeFileSync('sbom.cdx.json', `${JSON.stringify(parsed, null, 2)}\n`, { mode: 0o600 });
console.log(`Generated CycloneDX ${parsed.specVersion} SBOM.`);
