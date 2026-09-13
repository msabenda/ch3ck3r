#!/usr/bin/env node
'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

function walk(directory, output = []) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (['node_modules', '.git', '.vscode-test'].includes(entry.name)) continue;
        const file = path.join(directory, entry.name);
        if (entry.isDirectory()) walk(file, output);
        else output.push(file);
    }
    return output;
}

const secretPatterns = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bgh[opusr]_[A-Za-z0-9_]{20,}\b/,
    /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
];

const sourceFiles = walk('.').filter(file =>
    file !== path.join('scripts', 'security-gates.js') &&
    !file.endsWith('.vsix') &&
    !file.startsWith(`test${path.sep}`) &&
    !/\.(?:png|jpg|jpeg|gif|ico)$/.test(file));

const leaked = [];
for (const file of sourceFiles) {
    const content = fs.readFileSync(file, 'utf8');
    if (secretPatterns.some(pattern => pattern.test(content))) leaked.push(file);
}
if (leaked.length) {
    console.error(`Potential credentials found in: ${leaked.join(', ')}`);
    process.exit(1);
}

const expectedVsix = `ch3ck3r-sast-${require('../package.json').version}.vsix`;
if (fs.existsSync(expectedVsix)) {
    const entries = execFileSync('unzip', ['-Z1', expectedVsix], { encoding: 'utf8' })
        .split(/\r?\n/).filter(Boolean);
    const forbidden = entries.filter(entry =>
        /(^|\/)(?:node_modules|test|scripts|\.git|\.github)(\/|$)/.test(entry) ||
        /(^|\/)(?:\.env(?:\.|$)|.*\.(?:pem|key|p12|pfx|db)|package-lock\.json|BASELINE_AUDIT\.md|THREAT_MODEL\.md)$/.test(entry));
    if (forbidden.length) {
        console.error(`Forbidden VSIX entries:\n${forbidden.join('\n')}`);
        process.exit(1);
    }
    const required = ['extension/package.json', 'extension/src/extension.js', 'extension/SECURITY.md'];
    const missing = required.filter(entry => !entries.includes(entry));
    if (missing.length) {
        console.error(`Required VSIX entries missing: ${missing.join(', ')}`);
        process.exit(1);
    }
    console.log(`Inspected ${entries.length} entries in ${expectedVsix}.`);
}

console.log(`Secret gate checked ${sourceFiles.length} files.`);
