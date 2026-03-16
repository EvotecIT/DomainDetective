using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;

namespace DomainDetective;

internal static class DetectedDnsApplicationCatalog {
    private sealed class TxtDefinition {
        public string Id { get; init; } = string.Empty;
        public string Name { get; init; } = string.Empty;
        public DetectedDnsAppCategory Category { get; init; }
        public Microsoft365DetectionConfidence Confidence { get; init; } = Microsoft365DetectionConfidence.Moderate;
        public Func<string, bool> Match { get; init; } = null!;
    }

    private static readonly IReadOnlyList<TxtDefinition> TxtDefinitions = new[] {
        new TxtDefinition { Id = "microsoft-365", Name = "Microsoft 365", Category = DetectedDnsAppCategory.Productivity, Confidence = Microsoft365DetectionConfidence.Strong, Match = static value => value.StartsWith("ms=", StringComparison.OrdinalIgnoreCase) },
        new TxtDefinition { Id = "google-site-verification", Name = "Google Site Verification", Category = DetectedDnsAppCategory.Analytics, Match = static value => value.IndexOf("google-site-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "bing-webmaster", Name = "Bing Webmaster Verification", Category = DetectedDnsAppCategory.Analytics, Match = static value => value.StartsWith("msvalidate.1=", StringComparison.OrdinalIgnoreCase) },
        new TxtDefinition { Id = "atlassian", Name = "Atlassian", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("atlassian-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "facebook-domain-verification", Name = "Facebook Domain Verification", Category = DetectedDnsAppCategory.Verification, Match = static value => value.IndexOf("facebook-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "apple-domain-verification", Name = "Apple Domain Verification", Category = DetectedDnsAppCategory.Verification, Match = static value => value.IndexOf("apple-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "stripe", Name = "Stripe", Category = DetectedDnsAppCategory.Verification, Match = static value => value.IndexOf("stripe-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "mailchimp", Name = "Mailchimp", Category = DetectedDnsAppCategory.EmailMarketing, Confidence = Microsoft365DetectionConfidence.Weak, Match = static value => value.IndexOf("mailchimp-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("servers.mcsv.net", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "salesforce-marketing-cloud", Name = "Salesforce Marketing Cloud", Category = DetectedDnsAppCategory.EmailMarketing, Confidence = Microsoft365DetectionConfidence.Weak, Match = static value => value.IndexOf("sfmc-", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("_spf.salesforce.com", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("spf.salesforce.com", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "dynamics-365-marketing", Name = "Dynamics 365 Marketing", Category = DetectedDnsAppCategory.EmailMarketing, Match = static value => value.IndexOf("d365mktkey=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "hubspot-email", Name = "HubSpot Email", Category = DetectedDnsAppCategory.EmailMarketing, Confidence = Microsoft365DetectionConfidence.Weak, Match = static value => value.IndexOf("hubspotemail.net", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("hubspotemail", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "exclaimer", Name = "Exclaimer", Category = DetectedDnsAppCategory.EmailSignatures, Confidence = Microsoft365DetectionConfidence.Weak, Match = static value => value.IndexOf("spf.exclaimer.net", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("exclaimer.net", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "dmarc-analyzer", Name = "DMARC Analyzer", Category = DetectedDnsAppCategory.DmarcReporting, Match = static value => value.IndexOf("dmarcanalyzer", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("rep.dmarcanalyzer", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "docusign", Name = "DocuSign", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("docusign=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "dropbox", Name = "Dropbox", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("dropbox-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "box", Name = "Box", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("box-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("boxverify", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "zoom", Name = "Zoom", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("zoom-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "openai", Name = "OpenAI", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("openai-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "anthropic", Name = "Anthropic", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("anthropic-domain-verification-", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "1password", Name = "1Password", Category = DetectedDnsAppCategory.Security, Match = static value => value.IndexOf("1password-site-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "airtable", Name = "Airtable", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("airtable-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "linear", Name = "Linear", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("linear-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new TxtDefinition { Id = "hashicorp", Name = "HashiCorp", Category = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("hcp-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 }
    };

    public static IReadOnlyList<DetectedDnsApplication> DetectTxt(string normalizedTxt) {
        var apps = new List<DetectedDnsApplication>();
        for (var i = 0; i < TxtDefinitions.Count; i++) {
            var definition = TxtDefinitions[i];
            if (!definition.Match(normalizedTxt)) {
                continue;
            }

            apps.Add(new DetectedDnsApplication {
                Id = definition.Id,
                Name = definition.Name,
                Category = definition.Category,
                EvidenceKind = DetectedDnsAppEvidenceKind.TxtRecord,
                Confidence = definition.Confidence,
                Evidence = normalizedTxt,
                Source = "TXT"
            });
        }
        return apps;
    }

    public static IReadOnlyList<DetectedDnsApplication> DetectFromInventory(DnsInventoryAnalysis? dnsInventory) {
        if (dnsInventory == null) {
            return Array.Empty<DetectedDnsApplication>();
        }

        var apps = new List<DetectedDnsApplication>();

        var providerApp = FromDnsProvider(dnsInventory.Provider, dnsInventory.ProviderEvidence);
        if (providerApp != null) {
            apps.Add(providerApp);
        }

        var mailProviderApp = FromMailProvider(dnsInventory.MailProvider, dnsInventory.MailProviderEvidence);
        if (mailProviderApp != null) {
            apps.Add(mailProviderApp);
        }

        var cnameTargetApp = FromCnameTargetProvider(dnsInventory.CnameTargetProvider, dnsInventory.CnameTargetEvidence);
        if (cnameTargetApp != null) {
            apps.Add(cnameTargetApp);
        }

        AddTxtApplications(apps, dnsInventory.Queries);

        return apps
            .GroupBy(static app => $"{app.Id}|{app.EvidenceKind}|{app.Evidence}", StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .OrderBy(static app => app.Category)
            .ThenBy(static app => app.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static DetectedDnsApplication? FromDnsProvider(DnsProvider provider, IReadOnlyList<string>? evidence) {
        if (provider == DnsProvider.Unknown) {
            return null;
        }

        return new DetectedDnsApplication {
            Id = "dns-provider-" + provider.ToString().ToLowerInvariant(),
            Name = provider.ToString(),
            Category = DetectedDnsAppCategory.DnsHosting,
            EvidenceKind = DetectedDnsAppEvidenceKind.NsRecord,
            Confidence = Microsoft365DetectionConfidence.Strong,
            Evidence = FirstEvidence(evidence, provider.ToString()),
            Source = "DnsInventory.Provider"
        };
    }

    public static DetectedDnsApplication? FromMailProvider(MailProviderKind provider, IReadOnlyList<string>? evidence) {
        if (provider == MailProviderKind.Unknown) {
            return null;
        }

        var category = provider switch {
            MailProviderKind.Microsoft365 => DetectedDnsAppCategory.Productivity,
            MailProviderKind.Mimecast => DetectedDnsAppCategory.EmailSecurity,
            _ => DetectedDnsAppCategory.Other
        };

        return new DetectedDnsApplication {
            Id = "mail-provider-" + provider.ToString().ToLowerInvariant(),
            Name = provider.ToString(),
            Category = category,
            EvidenceKind = DetectedDnsAppEvidenceKind.MxRecord,
            Confidence = Microsoft365DetectionConfidence.Strong,
            Evidence = FirstEvidence(evidence, provider.ToString()),
            Source = "DnsInventory.MailProvider"
        };
    }

    public static DetectedDnsApplication? FromCnameTargetProvider(DnsCnameTargetProvider provider, IReadOnlyList<string>? evidence) {
        if (provider == DnsCnameTargetProvider.Unknown) {
            return null;
        }

        var category = provider switch {
            DnsCnameTargetProvider.Cloudflare => DetectedDnsAppCategory.CDN,
            DnsCnameTargetProvider.Amazon => DetectedDnsAppCategory.CDN,
            DnsCnameTargetProvider.Azure => DetectedDnsAppCategory.CDN,
            DnsCnameTargetProvider.Fastly => DetectedDnsAppCategory.CDN,
            _ => DetectedDnsAppCategory.Other
        };

        return new DetectedDnsApplication {
            Id = "cname-target-" + provider.ToString().ToLowerInvariant(),
            Name = provider.ToString(),
            Category = category,
            EvidenceKind = DetectedDnsAppEvidenceKind.CnameRecord,
            Confidence = Microsoft365DetectionConfidence.Strong,
            Evidence = FirstEvidence(evidence, provider.ToString()),
            Source = "DnsInventory.CnameTarget"
        };
    }

    private static string FirstEvidence(IReadOnlyList<string>? evidence, string fallback) {
        if (evidence == null || evidence.Count == 0) {
            return fallback;
        }

        for (var i = 0; i < evidence.Count; i++) {
            if (!string.IsNullOrWhiteSpace(evidence[i])) {
                return evidence[i];
            }
        }

        return fallback;
    }

    private static void AddTxtApplications(List<DetectedDnsApplication> apps, IReadOnlyList<DnsInventoryQuery>? queries) {
        if (queries == null || queries.Count == 0) {
            return;
        }

        foreach (var query in queries) {
            if (query.RecordType != DnsRecordType.TXT) {
                continue;
            }

            foreach (var record in query.Records) {
                if (record.Section != DnsInventorySection.Answer || record.Type != DnsRecordType.TXT) {
                    continue;
                }

                var normalized = NormalizeTxt(record.Data);
                if (normalized.Length == 0) {
                    continue;
                }

                var matches = DetectTxt(normalized);
                for (var i = 0; i < matches.Count; i++) {
                    apps.Add(matches[i]);
                }
            }
        }
    }

    private static string NormalizeTxt(string value) {
        var normalized = (value ?? string.Empty).Trim();
        if (normalized.Length >= 2 && normalized[0] == '"' && normalized[normalized.Length - 1] == '"') {
            normalized = normalized.Substring(1, normalized.Length - 2);
        }

        return normalized.Trim();
    }
}
