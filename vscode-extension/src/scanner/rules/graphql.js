/**
 * GraphQL-specific security rules
 */
module.exports = {
    rules: [
        {
            id: 'graphql-introspection-enabled',
            name: 'GraphQL Introspection Enabled (Production)',
            severity: 'medium',
            owasp: 'API9:2023 — Improper Assets Management',
            cwe: 200,
            description: 'GraphQL introspection query is enabled — attackers can dump the entire schema.',
            remediation: 'Disable introspection in production: process.env.NODE_ENV === "production" or explicit config check.',
            category: 'graphql',
            patterns: {
                javascript: [
                    { pattern: /buildSchema|graphqlHTTP|ApolloServer|GraphQLModule|expressGraphQL/gmi, contextCheck: (content) =>
                        !/(?:introspection\s*[:=]\s*false|introspection:\s*process\.env|introspection\s*!==?\s*true)/.test(content)
                    },
                ],
                python: [
                    { pattern: /graphene|strawberry|ariadne|graphql/gmi, contextCheck: (content) =>
                        !/(?:introspection\s*=\s*False|introspection\s*=\s*env)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'graphql-batch-query',
            name: 'GraphQL Batching/Aliasing Without Depth Limit',
            severity: 'medium',
            owasp: 'API4:2023 — Unrestricted Resource Consumption',
            cwe: 770,
            description: 'GraphQL endpoint allows batching or aliasing without depth/query complexity limits — enables DoS.',
            remediation: 'Set query depth limit, request cost analysis, rate-limit by user and IP.',
            category: 'graphql',
            patterns: {
                javascript: [
                    { pattern: /ApolloServer|expressGraphQL|graphqlHTTP/gmi, contextCheck: (content) =>
                        !/(?:validationRules|queryDepth|complexityLimit|maxDepth|queryComplexity|validateDepth|depthLimit)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'graphql-n-plus-one',
            name: 'GraphQL N+1 Query Pattern Risk',
            severity: 'low',
            owasp: 'API4:2023 — Unrestricted Resource Consumption',
            cwe: 770,
            description: 'GraphQL resolvers loading nested data per parent record — N+1 DB query problem can overload DB.',
            remediation: 'Use DataLoader (batch + cache), JOINs, or field-level resolver tuning to batch queries.',
            category: 'graphql',
            patterns: {
                javascript: [
                    { pattern: /\.findById|\.findOne|\.getById/gmi, contextCheck: (content, m) =>
                        /resolve|Resolver|resolver|field|Field/.test(content.slice(Math.max(0, m.index - 200), m.index + 100))
                    },
                ],
            }
        },
    ]
};
