using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using DomainDetective.Reports;
using System.IO;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;
using SixLabors.ImageSharp;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Excel composition across mixed view items (Index, Overview, per-domain sheets).
/// Implemented using OfficeIMO.Excel.
/// </summary>
public static partial class ExcelCompositionReport {
    private static Action<SheetComposer.ColumnComposer>? BuildMicrosoft365Block(DomainBucket bucket)
    {
        if (bucket.Microsoft365 == null)
        {
            return null;
        }

        var info = bucket.Microsoft365;
        if (DomainDetective.Reports.SectionProjectors.BuildMicrosoft365(info) is not { } sec)
        {
            return null;
        }

        return column =>
        {
            IEnumerable<(string Key, object? Value)> summaryRows = sec.Summary.Select(static kv => (kv.Key, (object?)kv.Value));
            column.Section("Microsoft 365").KeyValues(summaryRows);

            if (sec.Highlights.Count > 0)
            {
                column.Section("Highlights");
                column.BulletedList(sec.Highlights);
            }

            if (sec.Services.Count > 0)
            {
                var rows = sec.Services.Select(x => new { x.Service, x.Status, x.Confidence, x.Evidence }).ToList();
                column.TableFrom(rows, title: "Services", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (sec.Domains.Count > 0)
            {
                var rows = sec.Domains.Select(x => new { x.Domain, x.Role, x.Confidence, x.Evidence }).ToList();
                column.TableFrom(rows, title: "Tenant Domains", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (sec.Subdomains.Count > 0)
            {
                var rows = sec.Subdomains.Select(x => new { x.Name, x.Role, x.Resolution }).ToList();
                column.TableFrom(rows, title: "Known Subdomains", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (sec.Applications.Count > 0)
            {
                var rows = sec.Applications.Select(x => new { x.Name, x.Category, x.EvidenceKind, x.Confidence, x.Evidence }).ToList();
                column.TableFrom(rows, title: "Detected DNS Applications", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (sec.Evidence.Count > 0)
            {
                var rows = sec.Evidence.Select(x => new { x.Label, x.Category, x.Confidence, x.Evidence }).ToList();
                column.TableFrom(rows, title: "Evidence Ledger", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (sec.Findings.Count > 0)
            {
                var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(rows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildHttpBlock(DomainBucket bucket)
    {
        if (bucket.Http == null)
        {
            return null;
        }

        var http = bucket.Http;
        var projection = DomainDetective.Reports.SectionProjectors.BuildHttp(http);

        return column =>
        {
            column.Section("HTTP").KeyValues(new (string, object?)[]
            {
                ("Status", http.Status ?? "-"),
                ("Reachable", http.IsReachable ? "Yes" : "No"),
                ("Status Code", http.StatusCode?.ToString() ?? "-"),
                ("Grade", http.Grade != GradeLevel.Unknown ? http.Grade.ToString() : "-"),
                ("Method", http.RequestMethodUsed.ToString()),
                ("Effective URL", projection?.EffectiveUrl ?? (http.Url ?? http.Subject ?? "-")),
                ("Proxy", string.IsNullOrWhiteSpace(http.ProxyUsed) ? "-" : http.ProxyUsed),
                ("TLS Validation", http.TlsValidationDisabled ? "Disabled" : "Enabled"),
                ("HSTS", http.HstsPresent ? "Yes" : "No"),
                ("HTTP/2", http.Http2Supported ? "Yes" : "No"),
                ("HTTP/3", http.Http3Supported ? "Yes" : "No"),
                ("CSP frame-ancestors", http.CspFrameAncestorsPresent ? "Yes" : "No"),
                ("Missing Security Headers", http.MissingSecurityHeaders?.Count ?? 0),
                ("Info Disclosure Headers", http.InformationDisclosureHeaders?.Count ?? 0),
                ("Caching Headers", http.CachingHeaders?.Count ?? 0),
                ("Deprecated Present", http.DeprecatedHeadersPresent?.Count ?? 0),
                ("Deprecated Missing", http.MissingDeprecatedHeaders?.Count ?? 0),
                ("Mixed Content", http.MixedContentDetected ? "Yes" : "No"),
                ("Response Time", http.ResponseTime.ToString()),
                ("Body Length (bytes)", http.BodyLength?.ToString() ?? "-"),
                ("Body SHA-256", string.IsNullOrWhiteSpace(http.BodySha256) ? "-" : http.BodySha256)
            });

            try
            {
                var visited = http.Raw?.VisitedUrls;
                if (visited != null && visited.Count > 0)
                {
                    var rows = visited.Select((u, i) => new { Step = i + 1, Url = u }).ToList();
                    column.TableFrom(rows, title: "Redirect Chain", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                }
            }
            catch
            {
            }

            if (projection != null && projection.PresentSecurityHeaders.Count > 0)
            {
                var rows = projection.PresentSecurityHeaders.Select(x => new { x.Name, x.Value }).ToList();
                column.TableFrom(rows, title: "Present Security Headers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.MissingSecurityHeaders.Count > 0)
            {
                var rows = projection.MissingSecurityHeaders.Select(x => new { Header = x }).ToList();
                column.TableFrom(rows, title: "Missing Security Headers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.InformationDisclosureHeaders.Count > 0)
            {
                var rows = projection.InformationDisclosureHeaders.Select(x => new { x.Name, x.Value }).ToList();
                column.TableFrom(rows, title: "Information Disclosure Headers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.CachingHeaders.Count > 0)
            {
                var rows = projection.CachingHeaders.Select(x => new { x.Name, x.Value }).ToList();
                column.TableFrom(rows, title: "Caching Headers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && (projection.DeprecatedPresent.Count > 0 || projection.DeprecatedMissing.Count > 0))
            {
                var rows = new[]
                {
                    new { Group = "Deprecated Present", Headers = projection.DeprecatedPresent.Count > 0 ? string.Join(", ", projection.DeprecatedPresent) : "-" },
                    new { Group = "Deprecated Missing", Headers = projection.DeprecatedMissing.Count > 0 ? string.Join(", ", projection.DeprecatedMissing) : "-" }
                }.ToList();
                column.TableFrom(rows, title: "Deprecated Header Signals", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildIpEnrichmentBlock(DomainBucket bucket)
    {
        if (bucket.IpEnrichment == null)
        {
            return null;
        }

        var ip = bucket.IpEnrichment;
        var projection = DomainDetective.Reports.SectionProjectors.BuildIpEnrichment(ip);

        return column =>
        {
            column.Section("IP Enrichment").KeyValues(new (string, object?)[]
            {
                ("Status", ip.Status ?? "-"),
                ("Query OK", ip.QuerySucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(ip.FailureReason) ? "-" : ip.FailureReason),
                ("Unique IPs", ip.UniqueIpCount),
                ("Rows", ip.RowCount),
                ("ASNs", ip.DistinctAsnCount),
                ("Countries", ip.DistinctCountryCount),
                ("Capped", ip.ResultsCapped ? "Yes" : "No")
            });

            try
            {
                if (ip.AsnCounts != null && ip.AsnCounts.Count > 0)
                {
                    var rows = ip.AsnCounts
                        .OrderByDescending(kv => kv.Value)
                        .ThenBy(kv => kv.Key)
                        .Take(50)
                        .Select(kv => new { Asn = "AS" + kv.Key, Count = kv.Value })
                        .ToList();
                    column.TableFrom(rows, title: "ASN Counts (Top)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => { v.FreezeHeaderRow = true; v.NumericColumnFormats["Count"] = "0"; });
                }
            }
            catch
            {
            }

            try
            {
                if (ip.CountryCounts != null && ip.CountryCounts.Count > 0)
                {
                    var rows = ip.CountryCounts
                        .OrderByDescending(kv => kv.Value)
                        .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                        .Take(50)
                        .Select(kv => new { Country = kv.Key, Count = kv.Value })
                        .ToList();
                    column.TableFrom(rows, title: "Country Counts (Top)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => { v.FreezeHeaderRow = true; v.NumericColumnFormats["Count"] = "0"; });
                }
            }
            catch
            {
            }

            if (projection != null && projection.Rows.Count > 0)
            {
                const int maxRows = 500;
                var rows = projection.Rows
                    .Take(maxRows)
                    .Select(x => new
                    {
                        x.IpAddress,
                        Family = x.Family.ToString(),
                        SourceKind = x.SourceKind.ToString(),
                        x.SourceHost,
                        x.Ptr,
                        Asn = x.Asn.HasValue ? "AS" + x.Asn.Value : string.Empty,
                        x.AsName,
                        x.Cidr,
                        x.Country,
                        x.Region
                    })
                    .ToList();

                column.TableFrom(rows, title: "Enriched IP Rows (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildTyposquattingBlock(DomainBucket bucket)
    {
        if (bucket.Typosquatting == null)
        {
            return null;
        }

        var info = bucket.Typosquatting;
        var projection = DomainDetective.Reports.SectionProjectors.BuildTyposquatting(info);
        return column =>
        {
            column.Section("Typosquatting").KeyValues(new (string, object?)[]
            {
                ("Status", info.Status ?? "-"),
                ("Candidates", info.CandidateCount),
                ("Active", info.ActiveCount),
                ("Registered", info.RegisteredCount),
                ("Campaigns", info.Campaigns.Count),
                ("High-Priority Campaigns", info.HighPriorityCampaignCount),
                ("Critical Campaigns", info.CriticalCampaignCount),
                ("Content Lookalike", info.LikelyImpersonatingCount),
                ("Visual Clone", info.LikelyVisualCloneCount),
                ("Likely External", info.LikelyExternalCount),
                ("Likely Owned", info.LikelyOwnedCount),
                ("Ownership Profile", info.OwnershipProfileBuilt ? "Built" : "Not Built"),
                ("Content Profile", info.ContentProfileBuilt ? "Built" : "Not Built"),
                ("Visual Profile", info.VisualProfileBuilt ? "Built" : "Not Built"),
                ("Homoglyph Input", info.ContainsHomoglyphs ? "Yes" : "No")
            });

            if (projection != null && projection.Campaigns.Count > 0)
            {
                const int maxCampaignRows = 100;
                var campaignRows = projection.Campaigns
                    .Take(maxCampaignRows)
                    .Select(campaign => new
                    {
                        campaign.Label,
                        campaign.Severity,
                        campaign.CampaignScore,
                        Domains = campaign.CandidateCount,
                        Active = campaign.ActiveCount,
                        Reachable = campaign.ReachableWebCount,
                        Threat = campaign.ThreatListedCount,
                        Malicious = campaign.LikelyMaliciousCount,
                        Impersonation = campaign.LikelyImpersonationCount,
                        Content = campaign.LikelyImpersonatingCount,
                        Visual = campaign.LikelyVisualCloneCount,
                        TopDomain = string.IsNullOrWhiteSpace(campaign.TopCandidateDomain) ? "-" : campaign.TopCandidateDomain,
                        TopDisposition = string.IsNullOrWhiteSpace(campaign.TopCandidateDisposition) ? "-" : campaign.TopCandidateDisposition,
                        Actionability = string.IsNullOrWhiteSpace(campaign.Actionability) ? "-" : $"{campaign.Actionability} ({campaign.ActionabilityScore})",
                        Registrar = string.IsNullOrWhiteSpace(campaign.PrimaryRegistrar) ? "-" : $"{campaign.PrimaryRegistrar} ({campaign.RegistrarConcentrationPercent}%)",
                        Hosting = string.IsNullOrWhiteSpace(campaign.PrimaryHostingProvider) ? "-" : $"{campaign.PrimaryHostingProvider} ({campaign.HostingConcentrationPercent}%)",
                        Country = string.IsNullOrWhiteSpace(campaign.PrimaryCountry) ? "-" : $"{campaign.PrimaryCountry} ({campaign.CountryConcentrationPercent}%)",
                        Abuse = string.IsNullOrWhiteSpace(campaign.PrimaryAbuseContact) ? "-" : campaign.PrimaryAbuseContact,
                        Pivots = string.IsNullOrWhiteSpace(campaign.PivotSummary) ? "-" : campaign.PivotSummary,
                        ActionabilitySummary = string.IsNullOrWhiteSpace(campaign.ActionabilitySummary) ? "-" : campaign.ActionabilitySummary,
                        Action = string.IsNullOrWhiteSpace(campaign.RecommendedAction) ? "-" : campaign.RecommendedAction,
                        Summary = string.IsNullOrWhiteSpace(campaign.Summary) ? "-" : campaign.Summary
                    })
                    .ToList();
                column.TableFrom(campaignRows, title: "Campaigns", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.Rows.Count > 0)
            {
                const int maxRows = 300;
                var rows = projection.Rows
                    .Take(maxRows)
                    .Select(candidate => new
                    {
                        candidate.Domain,
                        candidate.RiskScore,
                        candidate.RiskLevel,
                        Disposition = string.IsNullOrWhiteSpace(candidate.Disposition) ? "-" : candidate.Disposition,
                        Risk = string.IsNullOrWhiteSpace(candidate.RiskSummary) ? "-" : candidate.RiskSummary,
                        Cluster = string.IsNullOrWhiteSpace(candidate.InfrastructureClusterLabel) ? "-" : $"{candidate.InfrastructureClusterLabel} ({candidate.InfrastructureClusterSize})",
                        candidate.Kind,
                        candidate.EditDistance,
                        Resolves = candidate.Resolves ? "Yes" : "No",
                        Registered = candidate.AppearsRegistered ? "Yes" : "No",
                        A = candidate.ACount,
                        AAAA = candidate.AaaaCount,
                        NS = candidate.NsCount,
                        MX = candidate.MxCount,
                        Registrar = string.IsNullOrWhiteSpace(candidate.Registrar) ? "-" : candidate.Registrar,
                        Http = candidate.HttpStatusCode?.ToString() ?? "-",
                        Threat = candidate.ThreatListed ? "Listed" : "-",
                        Tech = candidate.TechnologyCount,
                        IPs = candidate.EnrichedIpCount,
                        Owned = candidate.LikelyOwned ? $"Likely ({candidate.OwnershipConfidence})" : "-",
                        Ownership = string.IsNullOrWhiteSpace(candidate.OwnershipSummary) ? "-" : candidate.OwnershipSummary,
                        External = candidate.LikelyExternal ? $"Likely ({candidate.ExternalConfidence})" : "-",
                        Distinct = string.IsNullOrWhiteSpace(candidate.ExternalSummary) ? "-" : candidate.ExternalSummary,
                        Content = candidate.LikelyImpersonating ? $"Likely ({candidate.ContentSimilarityScore})" : (candidate.ContentSimilarityScore > 0 ? candidate.ContentSimilarityScore.ToString() : "-"),
                        Similarity = string.IsNullOrWhiteSpace(candidate.ContentSimilaritySummary) ? "-" : candidate.ContentSimilaritySummary,
                        Visual = candidate.LikelyVisualClone ? $"Likely ({candidate.VisualSimilarityScore})" : (candidate.VisualSimilarityScore > 0 ? candidate.VisualSimilarityScore.ToString() : "-"),
                        VisualType = string.IsNullOrWhiteSpace(candidate.VisualMatchType) ? "-" : candidate.VisualMatchType,
                        VisualDiff = candidate.VisualSimilarityDistance?.ToString() ?? "-",
                        VisualSummary = string.IsNullOrWhiteSpace(candidate.VisualSimilaritySummary) ? "-" : candidate.VisualSimilaritySummary,
                        Enrichment = string.IsNullOrWhiteSpace(candidate.EnrichmentSummary) ? "-" : candidate.EnrichmentSummary
                    })
                    .ToList();
                column.TableFrom(rows, title: "Candidates", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var findings = projection.Findings.Select(finding => new { finding.Severity, finding.Code, finding.Target, finding.Message }).ToList();
                column.TableFrom(findings, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildCaaBlock(DomainBucket bucket)
    {
        if (bucket.Caa == null)
        {
            return null;
        }

        var caa = bucket.Caa;
        return column =>
        {
            column.Section("CAA").KeyValues(new (string, object?)[]
            {
                ("Valid Records", caa.ValidRecords),
                ("Invalid Records", caa.InvalidRecords),
                ("Conflicting", caa.Conflicting ? "Yes" : "No"),
                ("Duplicate Issuers", caa.HasDuplicateIssuers ? "Yes" : "No")
            });

            void RenderList(string title, IReadOnlyList<string>? items)
            {
                if (items == null || items.Count == 0)
                {
                    return;
                }

                column.Section(title);
                column.BulletedList(items);
            }

            RenderList("Issue", caa.CanIssueCertificatesForDomain);
            RenderList("Wildcard Issue", caa.CanIssueWildcardCertificatesForDomain);
            RenderList("Mail Issue", caa.CanIssueMail);
            RenderList("Report Email", caa.ReportViolationEmail);
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildRpkiBlock(DomainBucket bucket)
    {
        if (bucket.Rpki == null)
        {
            return null;
        }

        var rpki = bucket.Rpki;
        return column =>
        {
            column.Section("RPKI").KeyValues(new (string, object?)[]
            {
                ("Total Checked", rpki.TotalChecked),
                ("Valid", rpki.ValidCount),
                ("All Valid", rpki.AllValid ? "Yes" : "No")
            });

            var rpkiResults = rpki.Results;
            if (rpkiResults != null && rpkiResults.Count > 0)
            {
                var rows = rpkiResults.Select(r => new { r.IpAddress, r.Prefix, r.Asn, Valid = r.Valid ? "Yes" : "No" }).ToList();
                column.TableFrom(rows, title: "RPKI Results", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Asn"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildZoneTransferBlock(DomainBucket bucket)
    {
        if (bucket.ZoneTransfer == null)
        {
            return null;
        }

        var zone = bucket.ZoneTransfer;
        return column =>
        {
            column.Section("Zone Transfer").KeyValues(new (string, object?)[]
            {
                ("Open", $"{zone.OpenCount}/{zone.TotalChecked}")
            });

            var zoneServerResults = zone.ServerResults;
            if (zoneServerResults != null && zoneServerResults.Count > 0)
            {
                var rows = zoneServerResults.Select(kv => new { Server = kv.Key, Open = kv.Value ? "Yes" : "No" }).ToList();
                column.TableFrom(rows, title: "Servers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildWildcardBlock(DomainBucket bucket)
    {
        if (bucket.Wildcard == null)
        {
            return null;
        }

        var wc = bucket.Wildcard;
        return column =>
        {
            column.Section("Wildcard DNS").KeyValues(new (string, object?)[] { ("Catch-All", wc.CatchAll ? "Yes" : "No") });
            var testedNames = wc.TestedNames;
            if (testedNames != null && testedNames.Count > 0)
            {
                column.Section("Tested Names").BulletedList(testedNames.ToArray());
            }
            var resolvedNames = wc.ResolvedNames;
            if (resolvedNames != null && resolvedNames.Count > 0)
            {
                column.Section("Resolved Names").BulletedList(resolvedNames.ToArray());
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildSubdomainsBlock(DomainBucket bucket)
    {
        if (bucket.Subdomains == null)
        {
            return null;
        }

        var sub = bucket.Subdomains;
        return column =>
        {
            string range = "-";
            if (sub.FirstSeenUtc.HasValue || sub.LastSeenUtc.HasValue)
            {
                var a = sub.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
                var b = sub.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
                range = a + " .. " + b;
            }

            var dnsVerification = sub.Raw?.VerifyStillResolves == true
                ? (sub.ResolutionReduced ? "Capped" : "Yes")
                : "No";

            column.Section("Subdomains (Discovery)").KeyValues(new (string, object?)[]
            {
                ("Status", sub.Status ?? "-"),
                ("Query OK", sub.QuerySucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(sub.FailureReason) ? "-" : sub.FailureReason),
                ("Subdomains", sub.SubdomainCount),
                ("CT Rows", sub.CertificateObservationCount),
                ("CT Processing", sub.ResultsCapped ? "Capped" : "OK"),
                ("Issuer Diversity", sub.DistinctIssuerCount),
                ("Seen (UTC)", range),
                ("DNS Verification", dnsVerification)
            });

            var issuerCounts = sub.IssuerCounts;
            if (issuerCounts != null && issuerCounts.Count > 0)
            {
                const int maxIssuers = 25;
                var issuerRows = issuerCounts
                    .OrderByDescending(kv => kv.Value)
                    .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                    .Take(maxIssuers)
                    .Select(kv => new { Issuer = kv.Key, Count = kv.Value })
                    .ToList();

                column.TableFrom(issuerRows, title: "Issuers (Top)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Count"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            var subdomains = sub.Subdomains;
            if (subdomains != null && subdomains.Count > 0)
            {
                const int maxRows = 200;
                var rows = subdomains
                    .Take(maxRows)
                    .Select(s => new
                    {
                        s.Name,
                        FirstSeenUtc = s.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-",
                        LastSeenUtc = s.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-",
                        Resolution = s.ResolutionStatus.ToString()
                    })
                    .ToList();

                column.TableFrom(rows, title: "Subdomains", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }
}


