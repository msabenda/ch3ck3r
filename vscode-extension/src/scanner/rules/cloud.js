/**
 * Cloud-specific misconfiguration rules
 */
module.exports = {
    rules: [
        {
            id: 's3-bucket-public-acl',
            name: 'S3 Bucket Public Write ACL',
            severity: 'critical',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 200,
            description: 'S3 bucket configured with public write access — anyone can upload/delete objects.',
            remediation: 'Remove public write ACLs. Use bucket policies with least privilege. Enable Block Public Access.',
            category: 'cloud',
            patterns: {
                all: [
                    { pattern: /(?:acl|ACL)[^=]*[:=]\s*['"`](?:public-read-write|public-write|authenticated-read)['"`]/gmi },
                    { pattern: /BlockPublicAccess|public_access_blocked.*\bfalse\b/gmi, contextCheck: (content) =>
                        /\bfalse\b/.test(content)
                    },
                    { pattern: /"Effect"\s*:\s*"Allow".*"Principal"\s*:\s*"\*"/gmi },
                    { pattern: /"Action"\s*:\s*"s3:\*"/gmi },
                ],
            }
        },
        {
            id: 'overly-permissive-iam',
            name: 'Overly Permissive IAM Policy',
            severity: 'high',
            owasp: 'API5:2023 — Broken Function Level Authorization',
            cwe: 732,
            description: 'IAM policy with * resource or action — grants more permissions than needed.',
            remediation: 'Apply least privilege: specify exact resources and actions. Use condition keys.',
            category: 'cloud',
            patterns: {
                all: [
                    { pattern: /"Resource"\s*:\s*"\*"/gmi },
                    { pattern: /"Action"\s*:\s*"\*"/gmi },
                    { pattern: /"Effect":"Allow".*"NotAction"/gmi },
                ],
            }
        },
        {
            id: 'terraform-secrets-plaintext',
            name: 'Terraform Secrets in Plaintext',
            severity: 'high',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'Hardcoded secrets in Terraform variable files (.tfvars).',
            remediation: 'Use Terraform variables with sensitive=true flag, or integrate with Vault/AWS Secrets Manager.',
            category: 'cloud',
            patterns: {
                all: [
                    { pattern: /(?:password|secret_key|api_token|private_key)\s*=\s*["'][^"']+["']/gmi, contextCheck: (content) =>
                        /\.(?:tfvars|tf|auto\.tfvars)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'k8s-privileged-container',
            name: 'Kubernetes Privileged Container',
            severity: 'critical',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 250,
            description: 'Kubernetes container configured as privileged — full host access.',
            remediation: 'Remove privileged: true. Use securityContext with specific capabilities only.',
            category: 'cloud',
            patterns: {
                all: [
                    { pattern: /privileged\s*[=:]\s*true/gmi, contextCheck: (content) =>
                        /kind:\s*Pod|kind:\s*Deployment|kind:\s*DaemonSet|kind:\s*StatefulSet|kind:\s*Job|kind:\s*CronJob/.test(content)
                    },
                ],
            }
        },
        {
            id: 'k8s-run-as-root',
            name: 'Kubernetes Pod Running as Root',
            severity: 'high',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 250,
            description: 'Pod security context missing runAsNonRoot: true and runAsUser.',
            remediation: 'Set securityContext.runAsNonRoot: true and runAsUser: 1000+.',
            category: 'cloud',
            patterns: {
                all: [
                    { pattern: /kind:\s*(?:Pod|Deployment|DaemonSet|StatefulSet|Job)/gmi, contextCheck: (content, m) =>
                        !content.slice(m.index, m.index + 2000).includes('runAsNonRoot') &&
                        !content.slice(m.index, m.index + 2000).includes('runAsUser')
                    },
                ],
            }
        },
    ]
};
