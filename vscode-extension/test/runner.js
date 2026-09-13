#!/usr/bin/env node
/**
 * Ch3ck3r — Performance Test Suite
 * Scans all vulnerable test files and reports findings + timing
 *
 * Usage: node test/runner.js
 *
 * Tests that Ch3ck3r can detect known issues in:
 *   Python, JavaScript, TypeScript, Go, Java, Ruby, Rust
 *   Dockerfile, OpenAPI spec, config files
 */

const path = require('path');
const fs = require('fs');
const { SecurityRules } = require('../src/scanner/rules/index');

const TEST_DIR = path.join(__dirname, 'vulnerable');
const rules = new SecurityRules();

const COLORS = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
};

function getExpected(filePath) {
    // Count // 🔴 comments
    const content = fs.readFileSync(filePath, 'utf-8');
    return (content.match(/🔴.*/g) || []).length;
}

async function run() {
    const files = fs.readdirSync(TEST_DIR)
        .filter(f => !f.startsWith('.'))
        .map(f => path.join(TEST_DIR, f));

    let totalFindings = 0;
    let totalExpected = 0;
    let totalTime = 0;

    console.log(COLORS.bold + '\n  ╔══════════════════════════════════════════════════════╗');
    console.log('  ║       Ch3ck3r SAST — Performance Test Suite          ║');
    console.log('  ╚══════════════════════════════════════════════════════╝\n' + COLORS.reset);

    for (const filePath of files) {
        const content = fs.readFileSync(filePath, 'utf-8');
        const ext = path.extname(filePath).toLowerCase();
        const basename = path.basename(filePath);
        const expected = getExpected(filePath);

        // Determine language
        const langMap = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
            '.go': 'go', '.java': 'java', '.rb': 'ruby', '.rs': 'rust',
        };
        const lang = basename === 'Dockerfile' ? 'dockerfile' : langMap[ext];

        if (!lang) continue;

        console.log(COLORS.cyan + `  📁 ${basename}` + COLORS.reset);
        console.log(COLORS.dim + `     Language: ${lang}` + COLORS.reset);

        const start = process.hrtime.bigint();

        let findings;
        if (basename === 'Dockerfile') {
            findings = rules.analyzeContainerfile(content, filePath);
        } else {
            findings = rules.analyzeCode(lang, content, filePath);
        }

        const end = process.hrtime.bigint();
        const elapsedMs = Number(end - start) / 1_000_000;

        totalFindings += findings.length;
        totalExpected += expected;
        totalTime += elapsedMs;

        const detectionRate = expected > 0
            ? Math.min(100, Math.round((findings.length / expected) * 100))
            : 100;

        const color = detectionRate >= 60 ? COLORS.green
                    : detectionRate >= 30 ? COLORS.yellow
                    : COLORS.red;

        console.log(`${color}     Detected: ${COLORS.bold}${findings.length}${COLORS.reset}${color} issues (${detectionRate}% of ~${expected} expected)${COLORS.reset}`);
        console.log(COLORS.dim + `     Time: ${elapsedMs.toFixed(1)}ms` + COLORS.reset);

        // Show top findings
        const bySeverity = {};
        for (const f of findings) {
            bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
        }
        if (Object.keys(bySeverity).length > 0) {
            console.log(`     Breakdown: ` + Object.entries(bySeverity)
                .map(([s, n]) => `${COLORS.bold}${s}${COLORS.reset}: ${n}`).join(', '));
        }

        // Show a few findings
        findings.slice(0, 3).forEach(f => {
            console.log(`       · [${COLORS.yellow}${f.severity}${COLORS.reset}] L${f.line} — ${f.ruleId} — ${f.description.substring(0, 60)}...`);
        });

        console.log('');
    }

    // Summary
    console.log(COLORS.bold + '  ════════════════════════════════════════════════════════');
    console.log(`  Summary:`);
    console.log(`  Total findings: ${totalFindings}`);
    console.log(`  Expected detections: ~${totalExpected}`);
    console.log(`  Total time: ${totalTime.toFixed(1)}ms`);
    console.log(`  Average per file: ${(totalTime / files.length).toFixed(1)}ms`);
    console.log(`  Files scanned: ${files.length}`);
    console.log('  ════════════════════════════════════════════════════════' + COLORS.reset);
}

run().catch(console.error);
