/**
 * rules.js — Security Rules Engine
 *
 * This file is now a thin re-export of the modular rules subsystem.
 * Rules have been split into domain modules in the rules/ subdirectory:
 *   api1-authz.js          — Broken Object Level Authorization (IDOR)
 *   api2-authentication.js — Broken Authentication (JWT, hardcoded secrets, session)
 *   api3-property-authz.js — Broken Object Property Level Authorization (mass assignment)
 *   api4-resource-*.js     — Unrestricted Resource Consumption (rate limits, pagination)
 *   api5-function-authz.js — Broken Function Level Authorization (RBAC)
 *   api6-business-flows.js — Unrestricted Access to Business Flows
 *   api7-ssrf.js           — Server-Side Request Forgery
 *   api8-misconfig.js      — Security Misconfiguration (CORS, SSL, debug, headers)
 *   api9-asset-mgmt.js     — Improper Asset Management (deprecated, versioning)
 *   api10-consumption.js   — Unsafe API Consumption
 *   cross-cutting.js       — SQL injection, command injection, XXE, crypto
 *   graphql.js             — GraphQL-specific issues
 *   container.js           — Docker/K8s misconfig
 *   secrets.js             — Secrets/tokens/credential detection
 *   cloud.js               — AWS/GCP/Terraform/K8s cloud misconfigs
 *   index.js               — Composite loader + helper functions
 *
 * The SecurityRules class from ./rules/index.js provides:
 *   - analyzeCode(language, content, filePath) -> finding[]
 *   - analyzeConfig(language, content, filePath) -> finding[]
 *   - analyzeApiSpec(language, content, filePath) -> finding[]
 *   - analyzeContainerfile(content, filePath) -> finding[]
 */
const { SecurityRules } = require('./rules/index');

module.exports = { SecurityRules };
