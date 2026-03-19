using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;

namespace DomainDetective;

internal static class DetectedDnsApplicationCatalog {
    public static IReadOnlyList<DetectedDnsApplication> DetectTxt(string normalizedTxt) {
        var apps = new List<DetectedDnsApplication>();
        var matches = DnsTxtDetectionCatalog.FindMatches(normalizedTxt);
        for (var i = 0; i < matches.Count; i++) {
            var definition = matches[i].Definition;
            if (!definition.ApplicationCategory.HasValue) {
                continue;
            }

            apps.Add(new DetectedDnsApplication {
                Id = definition.Id,
                Name = definition.Name,
                Category = definition.ApplicationCategory.Value,
                EvidenceKind = DetectedDnsAppEvidenceKind.TxtRecord,
                Confidence = definition.ApplicationConfidence,
                Evidence = matches[i].NormalizedValue,
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

                var matches = DetectTxt(record.Data);
                for (var i = 0; i < matches.Count; i++) {
                    apps.Add(matches[i]);
                }
            }
        }
    }
}
