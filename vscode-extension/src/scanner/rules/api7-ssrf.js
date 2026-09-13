/**
 * API7:2023 — Server Side Request Forgery
 * SSRF via user-controlled URLs, cloud metadata
 */
module.exports = {
    rules: [
        {
            id: 'ssrf-vulnerability',
            name: 'Server-Side Request Forgery (SSRF)',
            severity: 'critical',
            owasp: 'API7:2023 — Server Side Request Forgery',
            cwe: 918,
            description: 'User-controlled URL passed to server-side HTTP client. Attacker can scan internal subnets, access cloud metadata, exploit internal services.',
            remediation: 'Validate URLs against allowlist. Block private IPs (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Disable redirect following.',
            category: 'ssrf',
            applyToSpec: true,
            patterns: {
                python: [
                    { pattern: /requests\.(?:get|post|put|delete|head|options|patch)\(request\.(?:json|args|form|values)\.(?:get|__getitem__)\(['"]?(?:url|uri|target|webhook|callback|redirect|endpoint|link)['"]?/gmi },
                    { pattern: /httpx\.(?:get|post|put|delete)\(request\.(?:json|args)\.get\(['"](?:url|uri|target|webhook|callback)['"]/gmi },
                    { pattern: /urllib\.(?:request|parse)\.(?:urlopen|urlretrieve)\(\s*request/gmi },
                    { pattern: /aiohttp\.ClientSession.*request\.(?:json|args)\.get\(['"](?:url|uri)['"]/gmi },
                    { pattern: /url\s*=\s*request\.(?:args|form|json)\.get\(['"](?:url|uri|target)['"]/gmi },
                ],
                javascript: [
                    { pattern: /(?:axios|got|node-fetch|request|superagent|ky|needle)\.(?:get|post|put|delete|head|patch|request)\(req\.(?:body|query|params)\.(?:url|uri|target|webhook|callback|redirect|endpoint|link)/gmi },
                    { pattern: /fetch\(req\.(?:body|query|params)\.(?:url|uri|target|webhook|callback|redirect|endpoint)/gmi },
                    { pattern: /url\s*[:=]\s*req\.(?:body|query|params)\.(?:url|uri|target)/gmi },
                ],
                typescript: [
                    { pattern: /(?:axios|got|fetch)\(req\.(?:body|query|params)\.(?:url|uri|target|webhook|callback)/gmi },
                    { pattern: /url\s*[:=]\s*req\.(?:body|query|params)\.(?:url|uri)/gmi },
                    { pattern: /(?:axios|got|fetch)\(\s*(?:\w+\s+as\s+\w+\s*,\s*)?\w+\s*\)/gmi, contextCheck: (content) => {
                        // Check if a URL variable was assigned from req
                        const lines = content.split('\n');
                        let foundUrlAssign = false;
                        for (const l of lines) {
                            if (/url|uri|target|webhook|callback|endpoint/.test(l) && /req\./.test(l)) {
                                foundUrlAssign = true;
                                break;
                            }
                        }
                        return foundUrlAssign;
                    }},
                ],
                go: [
                    { pattern: /http\.(?:Get|Post|Head|Do)\((?:req\.|c\.|r\.|ctx\.)/gmi },
                    { pattern: /url\.Parse\(req\./gmi },
                ],
                java: [
                    { pattern: /new\s+URL\(\s*request\.getParameter\(/g },
                    { pattern: /RestTemplate\.(?:getForObject|postForObject|exchange)\([^)]*request\.getParameter/gmi },
                    { pattern: /WebClient\.(?:get|post|put|delete)\(\)\.uri\([^)]*request\.getParameter/gmi },
                ],
                kotlin: [
                    { pattern: /URL\(request\.getParameter/gmi },
                    { pattern: /webClient\.(?:get|post)\(\)\.uri\(request\.getParameter/gmi },
                ],
                php: [
                    { pattern: /file_get_contents\(\s*\$_?(?:GET|POST|REQUEST)\[['"](?:url|uri|target|webhook)['"]\]/gmi },
                    { pattern: /curl_exec.*\$_?(?:GET|POST|REQUEST)\[['"](?:url|uri|target)['"]\]/gmi },
                    { pattern: /curl_setopt\(\$ch,\s*CURLOPT_URL,\s*\$_/gmi },
                ],
                ruby: [
                    { pattern: /open\(\s*params\[['":](?:url|uri|target)['":]\]/gmi },
                    { pattern: /Net::HTTP\.get\(URI\(params\[['":](?:url|uri)['":]\]/gmi },
                ],
                rust: [
                    { pattern: /reqwest::(?:get|post|Client)\.new\(\)[^;]*params\[['"]?url['"]?/gmi },
                    { pattern: /reqwest::get\((?:\w+|format!)/gmi },
                    { pattern: /\burl\s*(?:=|:)\s*[\w.]+/gmi, contextCheck: (content) => /req|request|body/.test(content) },
                ],
            }
        },
        {
            id: 'ssrf-cloud-metadata',
            name: 'Cloud Metadata Service Access (SSRF Vector)',
            severity: 'critical',
            owasp: 'API7:2023 — Server Side Request Forgery',
            cwe: 918,
            description: 'Referencing cloud metadata endpoints (169.254.169.254, metadata.google.internal). If URL is user-controllable, cloud credentials can be stolen.',
            remediation: 'Block link-local addresses (169.254.0.0/16). Use URL allowlist and IP range validation middleware.',
            category: 'ssrf',
            patterns: {
                all: [
                    { pattern: /169\.254\.169\.254|metadata\.google\.internal|metadata\.amazonaws\.com|169\.254\.169\.253|100\.100\.100\.200|metadata\.azure\.com/gmi },
                ],
            }
        },
        {
            id: 'ssrf-url-schema-bypass',
            name: 'SSRF via URL Schema Manipulation',
            severity: 'high',
            owasp: 'API7:2023 — Server Side Request Forgery',
            cwe: 918,
            description: 'Potential URL parsing/schema manipulation in user-supplied URL — can bypass hostname validation.',
            remediation: 'Use a URL parser to extract + validate hostname. Block URL obfuscation: decimal IPs, unicode domains, ..@ scheme.',
            category: 'ssrf',
            patterns: {
                all: [
                    { pattern: /(?:file|gopher|dict|ftp|sftp):\/\//gmi, contextCheck: (content) =>
                        /url.*:/.test(content) || /URI.*parse/.test(content)
                    },
                    { pattern: /(?:0x7f000001|0x0a[0-9a-f]+|0xac1[0-9a-f]+|0xc0a8[0-9a-f]+)/gmi },
                ],
            }
        },
    ]
};
