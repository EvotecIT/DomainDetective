using System;
using System.Collections.Generic;
using DomainDetective.Providers.Dns;

namespace DomainDetective;

internal static class DnsTxtDetectionCatalog {
    internal sealed class Definition {
        public string Id { get; init; } = string.Empty;
        public string Name { get; init; } = string.Empty;
        public string? TechName { get; init; }
        public DetectedDnsAppCategory? ApplicationCategory { get; init; }
        public Microsoft365DetectionConfidence ApplicationConfidence { get; init; } = Microsoft365DetectionConfidence.Moderate;
        public DnsTxtSignals Signals { get; init; } = DnsTxtSignals.None;
        public string? SignalEvidence { get; init; }
        public Func<string, bool> Match { get; init; } = null!;
    }

    internal sealed class Match {
        public Definition Definition { get; init; } = null!;
        public string NormalizedValue { get; init; } = string.Empty;
    }

    private static readonly IReadOnlyList<Definition> Definitions = new[] {
        new Definition { Id = "microsoft-365", Name = "Microsoft 365", ApplicationCategory = DetectedDnsAppCategory.Productivity, ApplicationConfidence = Microsoft365DetectionConfidence.Strong, Signals = DnsTxtSignals.MicrosoftDomainVerification, SignalEvidence = "TXT: Microsoft domain verification token present (MS=)", Match = static value => value.StartsWith("ms=", StringComparison.OrdinalIgnoreCase) },
        new Definition { Id = "google-site-verification", Name = "Google Site Verification", TechName = "Google Site Verification", ApplicationCategory = DetectedDnsAppCategory.Analytics, Signals = DnsTxtSignals.GoogleSiteVerification, SignalEvidence = "TXT: Google site verification token present", Match = static value => value.IndexOf("google-site-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "bing-webmaster", Name = "Bing Webmaster Verification", TechName = "Bing Site Verification", ApplicationCategory = DetectedDnsAppCategory.Analytics, Signals = DnsTxtSignals.BingWebmasterVerification, SignalEvidence = "TXT: Microsoft/Bing site verification token present (msvalidate)", Match = static value => value.StartsWith("msvalidate.1=", StringComparison.OrdinalIgnoreCase) || value.StartsWith("msvalidate.01=", StringComparison.OrdinalIgnoreCase) },
        new Definition { Id = "atlassian", Name = "Atlassian", ApplicationCategory = DetectedDnsAppCategory.Productivity, Signals = DnsTxtSignals.AtlassianDomainVerification, SignalEvidence = "TXT: Atlassian domain verification token present", Match = static value => value.IndexOf("atlassian-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "statuspage", Name = "Atlassian Statuspage", TechName = "Atlassian Statuspage", Match = static value => value.IndexOf("status-page-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "facebook-domain-verification", Name = "Facebook Domain Verification", TechName = "Facebook Domain Verification", ApplicationCategory = DetectedDnsAppCategory.Verification, Signals = DnsTxtSignals.FacebookDomainVerification, SignalEvidence = "TXT: Facebook domain verification token present", Match = static value => value.IndexOf("facebook-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "apple-domain-verification", Name = "Apple Domain Verification", TechName = "Apple Domain Verification", ApplicationCategory = DetectedDnsAppCategory.Verification, Signals = DnsTxtSignals.AppleDomainVerification, SignalEvidence = "TXT: Apple domain verification token present", Match = static value => value.IndexOf("apple-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "stripe", Name = "Stripe", ApplicationCategory = DetectedDnsAppCategory.Verification, Signals = DnsTxtSignals.StripeVerification, SignalEvidence = "TXT: Stripe domain verification token present", Match = static value => value.IndexOf("stripe-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "mailchimp", Name = "Mailchimp", ApplicationCategory = DetectedDnsAppCategory.EmailMarketing, ApplicationConfidence = Microsoft365DetectionConfidence.Weak, Match = static value => value.IndexOf("mailchimp-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("servers.mcsv.net", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "salesforce-marketing-cloud", Name = "Salesforce Marketing Cloud", ApplicationCategory = DetectedDnsAppCategory.EmailMarketing, ApplicationConfidence = Microsoft365DetectionConfidence.Weak, Match = static value => value.IndexOf("sfmc-", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("_spf.salesforce.com", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("spf.salesforce.com", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "dynamics-365-marketing", Name = "Dynamics 365 Marketing", ApplicationCategory = DetectedDnsAppCategory.EmailMarketing, Match = static value => value.IndexOf("d365mktkey=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "hubspot-email", Name = "HubSpot Email", ApplicationCategory = DetectedDnsAppCategory.EmailMarketing, ApplicationConfidence = Microsoft365DetectionConfidence.Weak, Match = static value => value.IndexOf("hubspotemail.net", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("hubspotemail", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "exclaimer", Name = "Exclaimer", ApplicationCategory = DetectedDnsAppCategory.EmailSignatures, ApplicationConfidence = Microsoft365DetectionConfidence.Weak, Match = static value => value.IndexOf("spf.exclaimer.net", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("exclaimer.net", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "dmarc-analyzer", Name = "DMARC Analyzer", ApplicationCategory = DetectedDnsAppCategory.DmarcReporting, Match = static value => value.IndexOf("dmarcanalyzer", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("rep.dmarcanalyzer", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "docusign", Name = "DocuSign", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("docusign=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "dropbox", Name = "Dropbox", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("dropbox-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "box", Name = "Box", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("box-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("boxverify", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "zoom", Name = "Zoom", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("zoom-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "openai", Name = "OpenAI", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("openai-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "anthropic", Name = "Anthropic", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("anthropic-domain-verification-", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "1password", Name = "1Password", ApplicationCategory = DetectedDnsAppCategory.Security, Match = static value => value.IndexOf("1password-site-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "airtable", Name = "Airtable", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("airtable-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "linear", Name = "Linear", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("linear-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "hashicorp", Name = "HashiCorp", ApplicationCategory = DetectedDnsAppCategory.Productivity, Match = static value => value.IndexOf("hcp-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "yandex-site-verification", Name = "Yandex Site Verification", TechName = "Yandex Site Verification", Match = static value => value.IndexOf("yandex-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "pinterest-site-verification", Name = "Pinterest Site Verification", TechName = "Pinterest Site Verification", Match = static value => value.IndexOf("pinterest-site-verification=", StringComparison.OrdinalIgnoreCase) >= 0 },
        new Definition { Id = "ahrefs-site-verification", Name = "Ahrefs Site Verification", TechName = "Ahrefs Site Verification", Match = static value => value.IndexOf("ahrefs-site-verification=", StringComparison.OrdinalIgnoreCase) >= 0 }
    };

    public static IReadOnlyList<Match> FindMatches(string? value) {
        var normalized = NormalizeTxt(value);
        if (normalized.Length == 0) {
            return Array.Empty<Match>();
        }

        var matches = new List<Match>();
        for (var i = 0; i < Definitions.Count; i++) {
            var definition = Definitions[i];
            if (!definition.Match(normalized)) {
                continue;
            }

            matches.Add(new Match {
                Definition = definition,
                NormalizedValue = normalized
            });
        }

        return matches;
    }

    public static bool HasKnownMatch(string? value) {
        return FindMatches(value).Count > 0;
    }

    public static string NormalizeTxt(string? value) {
        var normalized = (value ?? string.Empty).Trim();
        if (normalized.Length >= 2 && normalized[0] == '"' && normalized[normalized.Length - 1] == '"') {
            normalized = normalized.Substring(1, normalized.Length - 2);
        }

        return normalized.Trim();
    }
}
