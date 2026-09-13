/**
 * API3:2023 — Broken Object Property Level Authorization
 * Mass assignment, sensitive data exposure in responses
 */
module.exports = {
    rules: [
        {
            id: 'mass-assignment',
            name: 'Mass Assignment / Property Injection',
            severity: 'high',
            owasp: 'API3:2023 — Broken Object Property Level Authorization',
            cwe: 915,
            description: 'Entire request body passed to update/create without filtering protected fields (role, is_admin, balance).',
            remediation: 'Use DTOs with explicit allowlists. Never pass request.json/req.body directly to DB. Use Pick/Omit/Partial types.',
            category: 'authorization',
            patterns: {
                python: [
                    { pattern: /\.(?:update|create|save)\([\s\S]*?(?:request\.json|request\.data|request\.form|request\.get_json)/gmi },
                    { pattern: /Model\.objects\.(?:update|create)\([\s\S]*?\*\*request/gmi },
                    { pattern: /setattr\(\w+,\s*\w+,\s*request/gmi },
                ],
                javascript: [
                    { pattern: /\.(?:update|updateOne|findByIdAndUpdate|findOneAndUpdate|findOneAndReplace|create|save)\([^)]*req\.(?:body|query)/gmi },
                    { pattern: /Object\.assign\(\w+,\s*req\.body/gmi },
                    { pattern: /\{\.\.\.req\.body/gmi },
                ],
                typescript: [
                    { pattern: /\.(?:update|updateOne|findByIdAndUpdate|findOneAndUpdate|create|save)\([^)]*req\.body/gmi },
                    { pattern: /Object\.assign\(\w+,\s*req\.body/gmi },
                    { pattern: /\.\.\.req\.body/gmi, contextCheck: (content, m) =>
                        !/(?:Pick|Partial|Omit)<|interface.*Body.*select/.test(content.slice(Math.max(0, m.index - 300), m.index))
                    },
                ],
                go: [
                    { pattern: /c\.Bind\(&[^)]+\).*\n.*db\.(?:Save|Update|Create|Model)/gmi },
                    { pattern: /json\.Unmarshal\(body.*\).*\n.*db\./gmi },
                ],
                java: [
                    { pattern: /@RequestBody\s+\w+\s+\w+.*\n.*(?:save|update|persist|merge)\(/gm },
                    { pattern: /BeanUtils\.copyProperties\([^)]*request/gmi },
                ],
                kotlin: [
                    { pattern: /@RequestBody.*\n.*(?:save|update|persist)\(/gm },
                ],
                ruby: [
                    { pattern: /\.update_all?\(?\s*params/gmi },
                    { pattern: /\.create\(?\s*params/gmi },
                ],
                php: [
                    { pattern: /->(?:update|create|save)\(\s*(?:\$request->all|\$_POST)/gmi },
                ],
                rust: [
                    { pattern: /serde_json::from_str.*req.*\n.*(?:update|create|save|insert)/gmi },
                ],
            }
        },
        {
            id: 'sensitive-property-in-response',
            name: 'Sensitive Properties Exposed in API Response',
            severity: 'high',
            owasp: 'API3:2023 — Broken Object Property Level Authorization',
            cwe: 200,
            description: 'Sensitive fields (password, ssn, credit_card, cvv, pin, secret_token) returned in API responses.',
            remediation: 'Use response DTOs explicitly excluding sensitive fields. Apply @JsonIgnore, @Expose, .select() without secrets.',
            category: 'information_disclosure',
            patterns: {
                python: [
                    { pattern: /(?:password|passwd|ssn|credit_card|creditcard|cvv|pin|secret_token)\s*[=:]\s*\w+/gmi, contextCheck: (content) =>
                        /(?:return\s+\{|"password"|'password'|serializer|marshal|jsonify|Response|dict\s*\()/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /res\.(?:json|send)\s*\(\s*(?:user|account|profile|userData)(?!\s*\.\s*map)/gmi },
                    { pattern: /return\s+\{[\s\S]{0,200}(?:password|ssn|creditCard|token|cvv|pin)[\s\S]{0,200}\}/gmi },
                ],
                java: [
                    { pattern: /(?:password|ssn|creditCard|cvv|pin)\s*(?:;|,|=|\n)/gmi, contextCheck: (content) =>
                        /(?:@Entity|@Table|@Document|class\s+\w+\s*\{)/.test(content) &&
                        !/@JsonIgnore|@Expose|@JsonProperty\(access/.test(content)
                    },
                ],
            }
        },
        {
            id: 'unvalidated-type-coercion',
            name: 'Unvalidated Type Coercion / Prototype Pollution',
            severity: 'high',
            owasp: 'API3:2023 — Broken Object Property Level Authorization',
            cwe: 1321,
            description: 'User input used to dynamically assign properties without type validation — object/prototype pollution risk.',
            remediation: 'Validate and sanitize dynamic property assignments. Avoid Object.assign with user input. Use Map instead.',
            category: 'injection',
            patterns: {
                javascript: [
                    { pattern: /\[req\.(?:body|query|params)\.\w+\]\s*[=:]/gmi },
                    { pattern: /\[['"]__proto__['"]\]|\[['"]constructor['"]\]/gmi },
                    { pattern: /\.assign\([^)]*__proto__/gmi },
                ],
            }
        },
    ]
};
