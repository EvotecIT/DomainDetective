using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class AgentReadinessRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[AgentReadinessCodes.LlmsTxtMissing] = new RecommendationAdvice {
            Code = AgentReadinessCodes.LlmsTxtMissing,
            Title = "llms.txt not found",
            Why = "Agent-facing documentation helps AI systems discover concise project, product, and API guidance.",
            How = "Publish /llms.txt with stable links to documentation, API references, search indexes, and usage guidance.",
            Domain = RecommendationDomain.Privacy,
            Tags = new[] { "agents", "llms.txt", "discovery" },
            Impact = "AI agents may rely on generic crawled content instead of curated guidance.",
            Effort = RecommendationEffort.Low,
            Verify = "GET https://<domain>/llms.txt returns 200 with text content."
        };
        map[AgentReadinessCodes.MarkdownMissing] = new RecommendationAdvice {
            Code = AgentReadinessCodes.MarkdownMissing,
            Title = "Markdown representation not discoverable",
            Why = "Markdown variants reduce parsing cost and ambiguity for AI agents.",
            How = "Serve Markdown with Accept: text/markdown or advertise a text/markdown alternate with an RFC 8288 Link header.",
            Domain = RecommendationDomain.Privacy,
            Tags = new[] { "agents", "markdown", "link-header" },
            Impact = "Agents may need to infer content from presentation-heavy HTML.",
            Effort = RecommendationEffort.Medium,
            Verify = "Request the page with Accept: text/markdown or inspect Link headers for rel=alternate; type=text/markdown."
        };
        map[AgentReadinessCodes.ContentSignalsMissing] = new RecommendationAdvice {
            Code = AgentReadinessCodes.ContentSignalsMissing,
            Title = "Content Signals policy not found",
            Why = "Content Signals express how content may be used for search, AI input, or AI training.",
            How = "Publish Content-Signal directives in robots.txt or as response headers where supported.",
            Domain = RecommendationDomain.Privacy,
            Tags = new[] { "agents", "content-signal", "robots" },
            Impact = "AI usage policy may be unclear to compatible crawlers.",
            Effort = RecommendationEffort.Low,
            Verify = "robots.txt or HTTP headers include Content-Signal: search=yes/no, ai-input=yes/no, ai-train=yes/no."
        };
        map[AgentReadinessCodes.ApiCatalogMissing] = new RecommendationAdvice {
            Code = AgentReadinessCodes.ApiCatalogMissing,
            Title = "API Catalog not found",
            Why = "RFC 9727 API Catalog gives agents a machine-readable entry point for API documentation.",
            How = "Publish /.well-known/api-catalog or advertise it with Link: <...>; rel=\"api-catalog\".",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "agents", "api-catalog", "rfc9727" },
            Impact = "Agents may not discover supported APIs or OpenAPI documents reliably.",
            Effort = RecommendationEffort.Medium,
            Verify = "GET https://<domain>/.well-known/api-catalog returns application/linkset+json."
        };
        map[AgentReadinessCodes.AgentSkillsMissing] = new RecommendationAdvice {
            Code = AgentReadinessCodes.AgentSkillsMissing,
            Title = "Agent Skills index not found",
            Why = "Agent Skills can describe task-specific instructions and resources for agent workflows.",
            How = "Publish an Agent Skills index such as /.well-known/agent-skills/index.json and link individual SKILL.md files.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "agents", "skills", "discovery" },
            Impact = "Agents miss explicit workflow guidance.",
            Effort = RecommendationEffort.Medium,
            Verify = "GET https://<domain>/.well-known/agent-skills/index.json returns JSON with a skills array."
        };
        map[AgentReadinessCodes.SecurityHeadersWeak] = new RecommendationAdvice {
            Code = AgentReadinessCodes.SecurityHeadersWeak,
            Title = "Agent trust headers are incomplete",
            Why = "AI agents and agent gateways still depend on web security signals such as HSTS, CSP, and content-type hardening.",
            How = "Serve HTTPS with HSTS and add CSP, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy where applicable.",
            Domain = RecommendationDomain.Http,
            Tags = new[] { "agents", "http", "headers" },
            Impact = "The site has weaker machine-verifiable trust posture.",
            Effort = RecommendationEffort.Medium,
            Verify = "Run the HTTP and AGENTREADINESS checks and confirm the trust category passes."
        };
    }
}
