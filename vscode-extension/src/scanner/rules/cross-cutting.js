/**
 * Cross-cutting rules: SQL injection, command injection, path traversal, LDAP, XXE, crypto
 */
module.exports = {
    rules: [
        {
            id: 'sql-injection',
            name: 'SQL Injection',
            severity: 'critical',
            owasp: 'API8:2023 — Injection',
            cwe: 89,
            description: 'Raw string interpolation/concatenation in SQL queries. Attacker can execute arbitrary SQL.',
            remediation: 'Use parameterized queries or ORM methods. Never concatenate user input into SQL strings.',
            category: 'injection',
            patterns: {
                python: [
                    { pattern: /execute\(f["']/gmi },
                    { pattern: /execute\(\s*['"][^'"]*\{[^}]*\}['"]/gmi },
                    { pattern: /cursor\.execute\(\s*['"][^'"]*['"]\s*%\s*(?:\(|\{|req)/gmi },
                    { pattern: /raw\(|text\(|SQL\(/gmi, contextCheck: (content) => /\+.*(?:req|input|param|user|request)/.test(content) },
                ],
                javascript: [
                    { pattern: /\.query\(`[^`]*\$\{[^}]*req[^}]*\}/gi },
                    { pattern: /\.query\(['"][^'"]*['"]\s*\+/gmi },
                    { pattern: /`SELECT[^`]*\$\{[^}]*req/gi },
                    { pattern: /\.raw\(|sequelize\.query\(|\.query\(\s*['"`]/gmi, contextCheck: (content, m) => {
                        const snippet = content.slice(m.index, m.index + 200);
                        return !/(\bwhere\b|\$[0-9]+|:param|@param)/.test(snippet) &&
                               /\+\s*req/.test(snippet);
                    }},
                ],
                go: [
                    { pattern: /fmt\.Sprintf\([^)]*db\./gmi },
                    { pattern: /db\.(?:Query|Exec|QueryRow|Prepare)\([^)]*\+/gmi },
                    { pattern: /`SELECT.*[+].*`/gmi },
                ],
                java: [
                    { pattern: /Statement\.(?:executeQuery|execute|executeUpdate)\([^)]*\+[^)]+\)/gmi },
                    { pattern: /"SELECT[^"]*"\+[^)]*request/gmi },
                ],
                ruby: [
                    { pattern: /execute\(\s*["'`][^"'`]*\#\{[^}]*params/gmi },
                ],
                php: [
                    { pattern: /mysqli_query\(\s*\$[^,]+,\s*["'`][^"'`]*\$/gmi },
                    { pattern: /\$.*->query\(["'`][^"'`]*\$/gmi },
                ],
                rust: [
                    { pattern: /sqlx::query\s*\(\s*format/gmi },
                    { pattern: /diesel::sql_query\s*\(\s*format/gmi },
                    { pattern: /format!\([^)]*\/\/[^)]*\)/gm, contextCheck: (content) => /sqlx::query|execute|select|delete|update|insert|from/i.test(content) },
                    { pattern: /format!\([^)]*"SELECT|format!\([^)]*"INSERT|format!\([^)]*"DELETE|format!\([^)]*"UPDATE/gmi },
                ],
            }
        },
        {
            id: 'command-injection',
            name: 'OS Command Injection',
            severity: 'critical',
            owasp: 'API8:2023 — Injection',
            cwe: 78,
            description: 'User input passed to OS command/shell execution. Attacker can run arbitrary commands.',
            remediation: 'Avoid shell calls with user input. Use execFile/spawn with args arrays. Validate strictly.',
            category: 'injection',
            patterns: {
                python: [
                    { pattern: /os\.system\([^)]*request/gmi },
                    { pattern: /subprocess\.(?:call|run|Popen|check_output)\([^)]*request/gmi },
                    { pattern: /subprocess\.(?:call|run|Popen|check_output)\([^)]*shell\s*=\s*True/gmi },
                ],
                javascript: [
                    { pattern: /exec\([^)]*req\.|execSync\([^)]*req/gmi },
                    { pattern: /exec\([^)]*req\./gmi },
                    { pattern: /spawn\([^)]*req\./gmi, contextCheck: (content, m) =>
                        !content.includes('shell: false') && !content.includes('shell:false')
                    },
                    { pattern: /child_process\.exec\([^)]*\${[^}]*req/gmi },
                ],
                go: [
                    { pattern: /exec\.Command\(["'`]sh["'`],\s*["'`]-c["'`],\s*[^)]*req/gmi },
                    { pattern: /exec\.CommandContext.*req\./gmi, contextCheck: (content) =>
                        !/\.Args\(/.test(content)
                    },
                ],
                java: [
                    { pattern: /Runtime\.getRuntime\(\)\.exec\([^)]*request/gmi },
                    { pattern: /ProcessBuilder\([^)]*request/gmi },
                ],
                php: [
                    { pattern: /(?:shell_exec|exec|system|passthru|popen)\s*\(\s*\$_/gmi },
                ],
                rust: [
                    { pattern: /Command::new\([^)]*\)\s*\.arg\([^)]*\)\s*\.output|Command::new\([^)]*\)\s*\.spawn/gmi },
                ],
            }
        },
        {
            id: 'path-traversal',
            name: 'Path Traversal / Local File Inclusion',
            severity: 'high',
            owasp: 'API8:2023 — Injection',
            cwe: 22,
            description: 'User input used in file path operations without sanitization. Attacker can read arbitrary files.',
            remediation: 'Use basename(), resolve() against safe root directory. Block ../ and null bytes.',
            category: 'injection',
            patterns: {
                python: [
                    { pattern: /open\([^)]*request\.(?:json|args|form)\.(?:get|__getitem__)\(/gmi },
                    { pattern: /Path\([^)]*request/gmi },
                ],
                javascript: [
                    { pattern: /fs\.(?:readFile|readFileSync|writeFile|writeFileSync|stat|access|createReadStream|unlink|readdir)\([^)]*req\.(?:body|query|params)/gmi },
                    { pattern: /path\.(?:join|resolve)\([^)]*req\.(?:body|query|params)/gmi },
                    { pattern: /sendFile\([^)]*req\./gmi },
                ],
                go: [
                    { pattern: /os\.(?:Open|ReadFile|Create|WriteFile)\([^)]*req/gmi },
                    { pattern: /ioutil\.ReadFile\([^)]*req/gmi },
                ],
                java: [
                    { pattern: /new\s+File\([^)]*request\.getParameter/gmi },
                ],
                rust: [
                    { pattern: /fs::read_to_string\(format!/gmi },
                    { pattern: /fs::(?:read|write)\([^)]*\+/gmi },
                ],
            }
        },
        {
            id: 'xpath-injection',
            name: 'Potential XPath / LDAP Injection',
            severity: 'high',
            owasp: 'API8:2023 — Injection',
            cwe: 643,
            description: 'User input interpolated in XPath or LDAP query string.',
            remediation: 'Use parameterized XPath queries or escape special characters. Use safe LDAP APIs.',
            category: 'injection',
            patterns: {
                java: [
                    { pattern: /XPathExpression.*\+=|xpath.*compile\([^)]*\+/gmi },
                    { pattern: /InitialDirContext|LdapName|SearchControls/gmi, contextCheck: (content) =>
                        /\+\s*request/.test(content)
                    },
                ],
            }
        },
        {
            id: 'xxe-vulnerability',
            name: 'XML External Entity (XXE) Injection',
            severity: 'critical',
            owasp: 'API8:2023 — Injection',
            cwe: 611,
            description: 'XML parser with external entity processing enabled — read local files, SSRF, DoS.',
            remediation: 'Disable DTD processing and external entity resolution in all XML parsers.',
            category: 'injection',
            patterns: {
                python: [
                    { pattern: /from lxml|xml\.etree|xml\.dom|xml\.sax/gmi, contextCheck: (content) =>
                        !/(?:resolve_entities\s*=\s*False|no_network\s*=\s*True|load_dtd\s*=\s*False)/.test(content)
                    },
                ],
                java: [
                    { pattern: /DocumentBuilderFactory|SAXParserFactory|XMLInputFactory/gmi, contextCheck: (content) =>
                        !/(?:setFeature.*DISALLOW_DTD|setFeature.*EXTERNAL_GENERAL|setExpandEntityReferences\s*\(\s*false)/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /parseString|xml2js|libxmljs|sax-parser/gmi, contextCheck: (content) =>
                        !/(?:noent|nonet|nosub|entityExpansionLimit)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'weak-crypto-algorithm',
            name: 'Weak or Deprecated Cryptographic Algorithm',
            severity: 'high',
            owasp: 'API8:2023 — Injection',
            cwe: 327,
            description: 'Use of MD5, SHA-1, DES, RC4, or ECB mode — allows collision or decryption.',
            remediation: 'Use SHA-256/512 for hashing, AES-GCM for encryption, or bcrypt/argon2 for passwords.',
            category: 'cryptography',
            patterns: {
                python: [
                    { pattern: /hashlib\.md5|hashlib\.sha1/gmi },
                    { pattern: /DES\.new|Crypto\.Cipher\.DES|ARC4/gmi },
                    { pattern: /AES\.new[^)]*MODE_ECB/gmi },
                ],
                javascript: [
                    { pattern: /crypto\.createHash\(['"`]md5['"`]|crypto\.createHash\(['"`]sha1['"`]/gmi },
                    { pattern: /['"`]aes-128-ecb['"`]|['"`]des['"`]|['"`]rc4['"`]/gmi },
                ],
                go: [
                    { pattern: /crypto\/md5|crypto\/sha1|crypto\/des|crypto\/rc4/gmi },
                ],
                java: [
                    { pattern: /MessageDigest\.getInstance\(["']MD5["']|MessageDigest\.getInstance\(["']SHA-1["']/gmi },
                    { pattern: /AES\/ECB|PBEWithMD5|DES\/CBC/gmi },
                ],
            }
        },
        {
            id: 'dynamic-eval',
            name: 'Dangerous Dynamic Code Execution',
            severity: 'high',
            owasp: 'API8:2023 — Injection',
            cwe: 95,
            description: 'Dynamic code execution (eval, exec, compile) with user input — arbitrary code execution.',
            remediation: 'Avoid eval/exec. Use safer alternatives: JSON.parse, Function constructor with validation, parsers.',
            category: 'injection',
            patterns: {
                python: [
                    { pattern: /eval\([^)]*request|exec\([^)]*request|compile\([^)]*request/gmi },
                ],
                javascript: [
                    { pattern: /eval\([^)]*req\./gmi },
                    { pattern: /new\s+Function\([^)]*req\./gmi },
                ],
                php: [
                    { pattern: /(?:eval|assert|call_user_func|array_map|preg_replace.*\/e)\s*\(\s*\$_/gmi },
                ],
            }
        },
    ]
};
