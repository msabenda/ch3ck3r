/**
 * API6:2023 — Unrestricted Access to Sensitive Business Flows
 * Business logic abuse, brute-force, data exfiltration
 */
module.exports = {
    rules: [
        {
            id: 'bulk-data-export',
            name: 'Bulk Data Export Without Rate/Quota Control',
            severity: 'medium',
            owasp: 'API6:2023 — Unrestricted Access to Sensitive Business Flows',
            cwe: 770,
            description: 'Data export/download endpoint without daily quota or speed limit — enables bulk exfiltration.',
            remediation: 'Implement daily export limits, CAPTCHA for sensitive data, and audit logging.',
            category: 'business_logic',
            patterns: {
                javascript: [
                    { pattern: /(?:export|download|backup|dump|extract)\s*(?:Data|Report|CSV|Excel|PDF)?[\s(]/gmi, contextCheck: (content, m) =>
                        !/(?:quota|limit|rateLimit|maxPerDay|exportLimit|daily)/.test(content.slice(0, m.index + 500))
                    },
                ],
                python: [
                    { pattern: /(?:export|generate_report|download_bulk|dump_data|extract_all)/gi, contextCheck: (content) =>
                        !/(?:quota|limit|max_per_day|export_limit|daily)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'no-brute-protection-auth',
            name: 'Missing Brute-Force Protection on Auth Endpoints',
            severity: 'medium',
            owasp: 'API6:2023 — Unrestricted Access to Sensitive Business Flows',
            cwe: 307,
            description: 'Login/signup/OTP/password-reset endpoints without lockout or rate limiting — enables brute force.',
            remediation: 'Implement account lockout, progressive delays, and CAPTCHA after failed attempts.',
            category: 'business_logic',
            patterns: {
                python: [
                    { pattern: /login|signin|signup|register|reset_password|forgot_password|verify_otp/gmi, contextCheck: (content) =>
                        !/(?:lockout|failed_attempts|LoginAttempt|throttle|rate_limit|recaptcha|captcha|login_attempts)/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /['"`](?:login|signin|signup|register|reset-password|forgot-password)['"`]/gmi, contextCheck: (content) =>
                        !/(?:lockout|rateLimit|rate-limiter|rate_limit|loginAttempt|failedAttempt|throttle|express-rate-limit|bottleneck)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'voting-abuse',
            name: 'Unprotected Voting/Feedback Endpoint',
            severity: 'low',
            owasp: 'API6:2023 — Unrestricted Access to Sensitive Business Flows',
            cwe: 770,
            description: 'Vote/rate/feedback endpoint without per-user or per-session deduplication — enables ballot stuffing.',
            remediation: 'Implement per-user uniqueness or session-based rate limiting on vote endpoints.',
            category: 'business_logic',
            patterns: {
                javascript: [
                    { pattern: /\/vote\/|\/rate\/|\/feedback\/|\/review\//gmi, contextCheck: (content) =>
                        !/(?:rateLimit|dedup|unique|throttle|per_user|user_id)/.test(content)
                    },
                ],
            }
        },
    ]
};
