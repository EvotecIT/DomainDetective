using DomainDetective.Toolbox.Models;

namespace DomainDetective.Toolbox.Services;

public sealed record ToolCapabilityInfo(
    string Title,
    string Description,
    IReadOnlyList<string> BrowserChecks,
    IReadOnlyList<string> DeeperChecks);

public static class ToolCapabilityPresentation {
    public static ToolCapabilityInfo Build(ToolDefinition tool, ToolsDeploymentMode deploymentMode) {
        ArgumentNullException.ThrowIfNull(tool);

        if (tool.Slug == "message-analyzer") {
            return new ToolCapabilityInfo(
                "Local browser analysis",
                "Message parsing and offline signature verification run in your browser without uploading content or querying DNS.",
                new[] { "Header provenance, route, and filtering evidence", "DKIM and ARC verification with supplied public keys", "Complete copyable text report" },
                new[] { "Explicit DNS key acquisition through CLI, PowerShell, or C#", "Batch files and HTML, Word, Excel, or Markdown exports" });
        }

        if (deploymentMode == ToolsDeploymentMode.HostedOnline) {
            return new ToolCapabilityInfo(
                "Online coverage",
                "This deployment can use the hosted analysis path when the tool needs network access beyond the browser sandbox.",
                new[] { "Live hosted analysis where configured", "Browser-safe fallback checks for DNS-oriented tools" },
                new[] { "CLI, PowerShell, and C# workflows for repeatable local automation" });
        }

        return tool.Slug switch {
            "m365-overview" => new ToolCapabilityInfo(
                "Partial browser support",
                "The browser edition builds a Microsoft 365 posture from public DNS and mail evidence, then marks tenant-only probes as deeper-run work.",
                new[] {
                    "SPF, DKIM, DMARC, MX, TLS-RPT, BIMI, CAA, and DANE evidence",
                    "Microsoft mail provider and DNS application fingerprints",
                    "Browser-safe evidence ledger and posture notes"
                },
                new[] {
                    "Tenant identity and Microsoft authentication probes",
                    "Tenant domain and Microsoft subdomain correlation",
                    "Full service detection and deeper recommendations"
                }),
            "domain-overview" => new ToolCapabilityInfo(
                "Partial browser support",
                "The browser edition runs the checks that work through browser DNS and keeps deeper network sections visible as deeper-run work.",
                new[] {
                    "DNS inventory, provider hints, and DNS application fingerprints",
                    "Core mail authentication and transport DNS controls",
                    "Browser-safe evidence ledger and posture notes"
                },
                new[] {
                    "HTTP headers, security.txt, and TLS certificate handshake details",
                    "RDAP registration data and DNSBL/exposure checks",
                    "Certificate Transparency subdomain discovery"
                }),
            "mta-sts" => new ToolCapabilityInfo(
                "Partial browser support",
                "The browser edition validates the DNS bootstrap record and leaves policy hosting checks to the deeper online run.",
                new[] {
                    "MTA-STS TXT bootstrap lookup",
                    "Record presence and syntax-oriented posture",
                    "Mail transport context from DNS"
                },
                new[] {
                    "HTTPS policy fetch and parsing",
                    "MX-to-policy host coverage",
                    "Full enforcement and duplicate-field validation"
                }),
            "dns-propagation" => new ToolCapabilityInfo(
                "Partial browser support",
                "The browser edition compares a compact public resolver sample so propagation checks still work in the browser.",
                new[] {
                    "Public resolver sample from the browser",
                    "Answer drift and resolver availability",
                    "Fast propagation signal for common records"
                },
                new[] {
                    "Broader DomainDetective resolver pool",
                    "Hosted cache refresh and wider vantage points",
                    "Repeatable CLI or PowerShell propagation audits"
                }),
            "raw-dns-query" => new ToolCapabilityInfo(
                "Runs in browser",
                "This workspace is designed for direct browser DNS-over-HTTPS queries and copyable DnsClientX examples.",
                new[] {
                    "Record-by-record DNS-over-HTTPS queries",
                    "Resolver selection for browser providers",
                    "Raw JSON answer review"
                },
                new[] {
                    "Local resolver targets and private network DNS",
                    "Scripted DnsClientX automation",
                    "Bulk checks across many hosts and record types"
                }),
            _ => BuildGenericStaticMap(tool)
        };
    }

    private static ToolCapabilityInfo BuildGenericStaticMap(ToolDefinition tool) {
        if (tool.BrowserCompatible) {
            return new ToolCapabilityInfo(
                "Runs in browser",
                "This check can run directly from the browser edition using DNS-over-HTTPS lookups in your browser.",
                BuildBrowserCompatibleChecks(tool),
                new[] {
                    "CLI, PowerShell, and C# automation",
                    "Local scripting across many domains",
                    "Resolver and environment choices outside the browser"
                });
        }

        if (tool.LiteCompatible) {
            return new ToolCapabilityInfo(
                "Partial browser support",
                "This check has a lighter browser edition here and a deeper path from PowerShell or the CLI.",
                new[] {
                    "Browser-safe public evidence",
                    "Clear status for checks that are not run here",
                    "Local workflow guidance"
                },
                new[] {
                    "Network probes that browser sandboxing blocks",
                    "Hosted or local validation",
                    "Full remediation evidence"
                });
        }

        return new ToolCapabilityInfo(
            "Guided locally",
            "This check needs network access that the browser edition cannot provide.",
            new[] {
                "Tool description and exact run commands",
                "Related workflows",
                "Install and usage links"
            },
            new[] {
                "Full analysis through CLI, PowerShell, or C#",
                "Network probes from your environment",
                "Repeatable local automation"
            });
    }

    private static IReadOnlyList<string> BuildBrowserCompatibleChecks(ToolDefinition tool) {
        return tool.Category switch {
            ToolCategory.EmailSecurity => new[] {
                "Public DNS records for this mail control",
                "parsing and posture classification",
                "Actionable findings and record details"
            },
            ToolCategory.Dns => new[] {
                "Public DNS answers through browser resolvers",
                "DomainDetective normalization and provider hints",
                "Record details and copyable evidence"
            },
            ToolCategory.TlsCert => new[] {
                "Public DNS records related to certificate posture",
                "parsing and posture classification",
                "Actionable findings and record details"
            },
            ToolCategory.ThreatIntel => new[] {
                "DNS-backed posture checks available to the browser",
                "findings for public takeover or blacklist signals",
                "Actionable result cards"
            },
            _ => new[] {
                "Browser-safe public evidence",
                "parsing and result cards",
                "Actionable findings"
            }
        };
    }
}
