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

        if (deploymentMode == ToolsDeploymentMode.HostedOnline) {
            return new ToolCapabilityInfo(
                "Online coverage",
                "This deployment can use the hosted DD analysis path when the tool needs network access beyond the browser sandbox.",
                new[] { "Live hosted analysis where configured", "Browser-safe fallback checks for DNS-oriented tools" },
                new[] { "CLI, PowerShell, and C# workflows for repeatable local automation" });
        }

        return tool.Slug switch {
            "m365-overview" => new ToolCapabilityInfo(
                "Partial browser support",
                "The GitHub Pages edition builds a Microsoft 365 posture from public DNS and mail evidence, then marks tenant-only probes as deeper-run work.",
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
                "The GitHub Pages edition runs the DD checks that are safe through browser DNS and keeps deeper network sections visible as deeper-run work.",
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
                "The web edition validates the DNS bootstrap record and leaves policy hosting checks to the deeper online run.",
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
                "The web edition compares a compact public resolver sample so propagation checks still work on GitHub Pages.",
                new[] {
                    "Public resolver sample from the browser",
                    "Answer drift and resolver availability",
                    "Fast propagation signal for common records"
                },
                new[] {
                    "Broader DD resolver pool",
                    "Hosted cache refresh and wider vantage points",
                    "Repeatable CLI or PowerShell propagation audits"
                }),
            "raw-dns-query" => new ToolCapabilityInfo(
                "Runs in browser",
                "This workspace is designed for direct browser DNS-over-HTTPS queries and copyable DnsClientX examples.",
                new[] {
                    "Record-by-record DNS-over-HTTPS queries",
                    "Resolver selection for browser-safe providers",
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
                "This check can run directly from the GitHub Pages edition using browser-safe DD lookups.",
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
                "This check has a lighter web edition here and a deeper DD path outside GitHub Pages.",
                new[] {
                    "Browser-safe public evidence",
                    "Clear status for checks that are not run here",
                    "Local workflow guidance"
                },
                new[] {
                    "Network probes that browser sandboxing blocks",
                    "Hosted or local DD validation",
                    "Full remediation evidence"
                });
        }

        return new ToolCapabilityInfo(
            "Guided locally",
            "This check needs network access that the GitHub Pages browser edition cannot provide.",
            new[] {
                "Tool description and exact run commands",
                "Related DD workflows",
                "Install and usage links"
            },
            new[] {
                "Full DD analysis through CLI, PowerShell, or C#",
                "Network probes from your environment",
                "Repeatable local automation"
            });
    }

    private static IReadOnlyList<string> BuildBrowserCompatibleChecks(ToolDefinition tool) {
        return tool.Category switch {
            ToolCategory.EmailSecurity => new[] {
                "Public DNS records for this mail control",
                "DD parsing and posture classification",
                "Actionable findings and record details"
            },
            ToolCategory.Dns => new[] {
                "Public DNS answers through browser-safe resolvers",
                "DD normalization and provider hints",
                "Record details and copyable evidence"
            },
            ToolCategory.TlsCert => new[] {
                "Public DNS records related to certificate posture",
                "DD parsing and posture classification",
                "Actionable findings and record details"
            },
            ToolCategory.ThreatIntel => new[] {
                "DNS-backed posture checks available to the browser",
                "DD findings for public takeover or blacklist signals",
                "Actionable result cards"
            },
            _ => new[] {
                "Browser-safe public evidence",
                "DD parsing and result cards",
                "Actionable findings"
            }
        };
    }
}
