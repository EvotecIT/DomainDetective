using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using DomainDetective.Views;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

internal static class DomainOverviewPresentation
{
    public static IReadOnlyList<DomainOverviewDetailCardView> BuildSnapshotCards(DomainOverviewInfo? info)
    {
        if (info == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return new[]
        {
            BuildAssessmentSnapshotCard(info),
            BuildMailSnapshotCard(info),
            BuildWebSnapshotCard(info),
            BuildProviderSnapshotCard(info),
            BuildExposureSnapshotCard(info),
            BuildRegistrationSnapshotCard(info)
        };
    }

    public static IReadOnlyList<string> BuildSnapshotHighlights(DomainOverviewInfo? info)
    {
        if (info == null)
        {
            return Array.Empty<string>();
        }

        var lines = new List<string>();

        if (!string.IsNullOrWhiteSpace(info.MailProvider) && !string.Equals(info.MailProvider, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            lines.Add("Mail provider: " + info.MailProvider);
        }

        if (!string.IsNullOrWhiteSpace(info.DnsProvider) && !string.Equals(info.DnsProvider, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            lines.Add("DNS provider: " + info.DnsProvider);
        }

        var failingChecks = info.MailDnsChecks
            .Concat(info.WebRegistrationChecks)
            .Where(static check => check.State == AggregateCheckState.Fail || check.State == AggregateCheckState.Warning)
            .Take(4)
            .Select(static check => check.Label + ": " + check.Value + " (" + check.Detail + ")");
        lines.AddRange(failingChecks);

        if (lines.Count < 5 && info.DaysUntilExpiration.HasValue)
        {
            lines.Add("Registration: " + FormatExpiryLabel(info.DaysUntilExpiration.Value));
        }

        if (lines.Count < 5 && info.SubdomainCount > 0)
        {
            lines.Add("Subdomains observed: " + info.SubdomainCount);
        }

        if (lines.Count < 5)
        {
            lines.AddRange(info.Summary.Hints.Take(5 - lines.Count));
        }

        return lines
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToArray();
    }

    private static DomainOverviewDetailCardView BuildAssessmentSnapshotCard(DomainOverviewInfo info)
    {
        var samples = info.Assessments
            .Take(3)
            .Select(static assessment => assessment.Category + ": " + assessment.Message)
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "Assessments",
            ValueLabel = info.TotalAssessments.ToString(),
            Summary = "DD merged mail, web, registration, and exposure findings into the overview assessment count shown here.",
            Tags = new[]
            {
                "Warnings: " + info.WarningCount,
                "Errors: " + info.ErrorCount
            },
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildMailSnapshotCard(DomainOverviewInfo info)
    {
        var passCount = info.MailDnsChecks.Count(static check => check.State == AggregateCheckState.Pass);
        var failCount = info.MailDnsChecks.Count(static check => check.State == AggregateCheckState.Fail);
        var samples = info.MailDnsChecks
            .Where(static check => check.State == AggregateCheckState.Fail || check.State == AggregateCheckState.Warning)
            .Take(3)
            .Select(static check => check.Label + ": " + check.Value)
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "Mail and DNS",
            ValueLabel = passCount + " pass",
            Summary = "The mail and DNS posture combines SPF, DKIM, DMARC, MX, transport policy, and DNS infrastructure into one DD control surface.",
            Tags = new[]
            {
                "Failing controls: " + failCount,
                "Checks: " + info.MailDnsChecks.Count
            },
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildWebSnapshotCard(DomainOverviewInfo info)
    {
        var samples = new List<string>();
        if (info.HttpReachable)
        {
            samples.Add("HTTP posture: grade " + info.HttpGrade);
        }

        samples.Add("Security.txt: " + (info.SecurityTxtPublished ? "Published" : "Missing"));
        if (info.Certificate != null && !string.IsNullOrWhiteSpace(info.Certificate.CertificateSubject))
        {
            samples.Add("Certificate subject: " + info.Certificate.CertificateSubject);
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Web posture",
            ValueLabel = info.HttpReachable ? "Grade " + info.HttpGrade : "Offline",
            Summary = "DD blends HTTP reachability, certificate posture, and disclosure metadata to summarize the exposed web surface.",
            Tags = new[]
            {
                info.HttpReachable ? "HTTP reachable" : "HTTP not reachable",
                info.SecurityTxtPublished ? "Security.txt published" : "Security.txt missing"
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Take(3).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildProviderSnapshotCard(DomainOverviewInfo info)
    {
        var samples = info.DetectedApplications
            .OrderByDescending(static item => (int)item.Confidence)
            .Take(3)
            .Select(static item => item.Name + ": " + item.EvidenceKind)
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "Providers",
            ValueLabel = FormatProviderValue(info.MailProvider),
            Summary = "Mail routing, authoritative DNS, and detected DNS application fingerprints shape the provider footprint DD reports here.",
            Tags = new[]
            {
                "DNS: " + FormatProviderValue(info.DnsProvider),
                "Detected apps: " + info.DetectedApplicationCount
            },
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildExposureSnapshotCard(DomainOverviewInfo info)
    {
        var samples = info.SubdomainSample
            .Take(3)
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "Exposure",
            ValueLabel = info.SubdomainCount + " subdomains",
            Summary = "DD uses subdomain discovery and external application clues to outline the domain’s visible exposure surface.",
            Tags = new[]
            {
                "Detected apps: " + info.DetectedApplicationCount,
                info.Subdomains != null ? "Resolving: " + info.Subdomains.ResolvesCount : "Subdomain evidence limited"
            },
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildRegistrationSnapshotCard(DomainOverviewInfo info)
    {
        var samples = new List<string>();
        if (info.Rdap != null && !string.IsNullOrWhiteSpace(info.Rdap.Registrar))
        {
            samples.Add("Registrar: " + info.Rdap.Registrar);
        }

        samples.AddRange(info.Summary.Hints.Take(2));

        return new DomainOverviewDetailCardView
        {
            Title = "Registration",
            ValueLabel = info.DaysUntilExpiration.HasValue ? FormatExpiryLabel(info.DaysUntilExpiration.Value) : "Expiry unknown",
            Summary = "Registration timing, registrar context, and DD hinting combine here to summarize the registration and lifecycle posture.",
            Tags = new[]
            {
                "Hints: " + info.Summary.Hints.Count,
                info.DaysUntilExpiration.HasValue ? "Days remaining: " + info.DaysUntilExpiration.Value : "Expiry not observed"
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(3).ToArray()
        };
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildHighlightCards(DomainOverviewInfo? info)
    {
        if (info == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        var cards = new List<DomainOverviewDetailCardView>
        {
            BuildProviderNotesCard(info),
            BuildWebRegistrationNotesCard(info),
            BuildExposureNotesCard(info)
        };

        return cards.Where(static card => card.Tags.Count > 0 || card.Samples.Count > 0).ToArray();
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildMailCards(DomainOverviewInfo? info)
    {
        if (info == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        var cards = new List<DomainOverviewDetailCardView>();
        if (info.Spf != null)
        {
            cards.Add(BuildSpfCard(info.Spf));
        }

        if (info.Dkim.Count > 0)
        {
            cards.Add(BuildDkimCard(info.Dkim));
        }

        if (info.Dmarc != null)
        {
            cards.Add(BuildDmarcCard(info.Dmarc));
        }

        if (info.Mx != null)
        {
            cards.Add(BuildMxCard(info.Mx));
        }

        cards.Add(BuildTransportCard(info));
        cards.Add(BuildDnsInfrastructureCard(info));
        return cards;
    }

    private static DomainOverviewDetailCardView BuildProviderNotesCard(DomainOverviewInfo info)
    {
        var tags = new List<string>
        {
            "Mail: " + FormatProviderValue(info.MailProvider),
            "DNS: " + FormatProviderValue(info.DnsProvider),
            "Apps: " + info.DetectedApplicationCount
        };

        var samples = new List<string>();
        samples.AddRange(info.DetectedApplications
            .OrderByDescending(static item => (int)item.Confidence)
            .Take(4)
            .Select(static item => item.Name + ": " + item.EvidenceKind));

        if (samples.Count < 4)
        {
            samples.AddRange(info.Highlights
                .Where(static item => item.Contains("provider", StringComparison.OrdinalIgnoreCase) || item.Contains("app", StringComparison.OrdinalIgnoreCase))
                .Take(4 - samples.Count));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Provider notes",
            ValueLabel = info.DetectedApplicationCount + " provider hints",
            Summary = "DD combined DNS inventory, routing, and application fingerprints to summarize the provider footprint behind this domain.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildWebRegistrationNotesCard(DomainOverviewInfo info)
    {
        var tags = new List<string>
        {
            info.HttpReachable ? "HTTP reachable" : "HTTP not reachable",
            "Security.txt: " + (info.SecurityTxtPublished ? "published" : "missing")
        };

        if (info.DaysUntilExpiration.HasValue)
        {
            tags.Add("Expiry: " + FormatExpiryLabel(info.DaysUntilExpiration.Value));
        }

        var samples = new List<string>();
        if (info.HttpReachable)
        {
            samples.Add("Web posture: grade " + info.HttpGrade);
        }

        samples.AddRange(info.Summary.Hints.Take(3));

        if (info.Rdap != null && !string.IsNullOrWhiteSpace(info.Rdap.Registrar))
        {
            samples.Add("Registrar: " + info.Rdap.Registrar);
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Web and registration notes",
            ValueLabel = info.HttpReachable ? "Grade " + info.HttpGrade : "Offline",
            Summary = "DD blended web reachability, certificate/security metadata, and registration timing into these posture notes.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildExposureNotesCard(DomainOverviewInfo info)
    {
        var subdomains = info.Subdomains;
        var tags = new List<string>
        {
            "Observed: " + info.SubdomainCount
        };

        if (subdomains != null)
        {
            tags.Add("Resolving: " + subdomains.ResolvesCount);
            tags.Add("High sensitivity: " + subdomains.SensitiveHighCount);
            if (subdomains.AiExposureCount > 0)
            {
                tags.Add("AI-signaled: " + subdomains.AiExposureCount);
            }
        }

        var samples = new List<string>();
        if (subdomains != null)
        {
            samples.AddRange(subdomains.Highlights.Take(3));
        }

        if (samples.Count < 4)
        {
            samples.AddRange(info.SubdomainSample.Take(4 - samples.Count));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Exposure notes",
            ValueLabel = info.SubdomainCount + " subdomain(s)",
            Summary = "DD used subdomain discovery, naming sensitivity, and certificate context to summarize the external exposure profile.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildEvidenceCards(DomainOverviewInfo? info)
    {
        if (info == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        var cards = new List<DomainOverviewDetailCardView>
        {
            BuildProviderCard(info),
            BuildMailPostureCard(info),
            BuildApplicationFootprintCard(info)
        };

        if (info.Http != null || info.Certificate != null || info.SecurityTxt != null)
        {
            cards.Add(BuildWebEvidenceCard(info));
        }

        if (info.Subdomains != null && info.Subdomains.SubdomainCount > 0)
        {
            cards.Add(BuildExposureEvidenceCard(info.Subdomains));
        }

        if (info.Rdap != null)
        {
            cards.Add(BuildRegistrationEvidenceCard(info.Rdap));
        }

        return cards;
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildEvidenceSummaryCards(DomainOverviewInfo? info)
    {
        if (info == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        var cards = new List<DomainOverviewDetailCardView>
        {
            BuildEvidenceCoverageCard(info),
            BuildProviderSurfaceCard(info)
        };

        if (info.Http != null || info.Certificate != null || info.SecurityTxt != null || info.Rdap != null || info.Dnsbl != null)
        {
            cards.Add(BuildWebRegistrationSurfaceCard(info));
        }

        if (info.Subdomains != null && info.Subdomains.SubdomainCount > 0)
        {
            cards.Add(BuildExposureSurfaceCard(info.Subdomains));
        }

        return cards;
    }

    private static DomainOverviewDetailCardView BuildSpfCard(SpfRecordInfo info)
    {
        var tags = new List<string>
        {
            info.SpfRecordExists ? "Published" : "Missing",
            info.AllMechanism ?? "No all policy"
        };

        tags.Add(info.DnsLookupsCount + "/10 lookups");
        if (info.HasRedirect)
        {
            tags.Add("Redirect");
        }

        if (info.HasExp)
        {
            tags.Add("exp=");
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.SpfRecord))
        {
            samples.Add(Truncate(info.SpfRecord, 120));
        }

        samples.AddRange(info.Highlights.Take(2));
        if (samples.Count < 3)
        {
            samples.AddRange(info.ResolvedIncludeRecords.Take(2).Select(static value => "Include: " + value));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "SPF policy",
            ValueLabel = info.SpfRecordExists ? (info.AllMechanism ?? "Published") : "Missing",
            Summary = $"DD evaluated SPF structure, lookup budget, includes, and flattening posture for the domain.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildDkimCard(IReadOnlyList<DkimRecordInfo> selectors)
    {
        var validSelectors = selectors.Count(static item => item.ValidPublicKey && !item.WeakKey);
        var tags = new List<string>
        {
            validSelectors + "/" + selectors.Count + " valid"
        };

        if (selectors.Any(static item => item.WeakKey))
        {
            tags.Add("Weak key present");
        }

        if (selectors.Any(static item => item.OldKey))
        {
            tags.Add("Old key");
        }

        var samples = selectors
            .OrderByDescending(static item => item.ValidPublicKey)
            .ThenByDescending(static item => item.KeyLength)
            .Take(4)
            .Select(static item => item.Selector + ": " + (item.PublicKeyExists ? item.KeyLength + " bit " + item.KeyType : "no key"))
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "DKIM selectors",
            ValueLabel = selectors.Count + " selector(s)",
            Summary = "DD checked discovered selectors for key presence, key strength, and selector record quality.",
            Tags = tags,
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildDmarcCard(DmarcRecordInfo info)
    {
        var tags = new List<string>
        {
            info.DmarcRecordExists ? "Published" : "Missing",
            string.IsNullOrWhiteSpace(info.Policy) ? "No p=" : "p=" + info.Policy,
            "rua " + (info.MailtoRua.Count + info.HttpRua.Count)
        };

        if (info.WeakPolicy)
        {
            tags.Add("Weak policy");
        }

        if (info.UnauthorizedExternalReportDomains.Count > 0)
        {
            tags.Add("Unauthorized rua");
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.DmarcRecord))
        {
            samples.Add(Truncate(info.DmarcRecord, 120));
        }

        samples.AddRange(info.Highlights.Take(2));
        samples.AddRange(info.MailtoRua.Take(2).Select(static value => "rua: " + value));

        return new DomainOverviewDetailCardView
        {
            Title = "DMARC policy",
            ValueLabel = info.DmarcRecordExists ? (string.IsNullOrWhiteSpace(info.Policy) ? "Published" : info.Policy.ToUpperInvariant()) : "Missing",
            Summary = "DD validated policy mode, alignment, and reporting destinations for the domain DMARC record.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildMxCard(MxInfo info)
    {
        var tags = new List<string>
        {
            info.MxRecordExists ? info.MxRecords.Count + " record(s)" : "Missing",
            info.HasBackupServers ? "Backup MX" : "Single path",
            info.Ipv6Supported ? "IPv6" : "No IPv6"
        };

        if (!string.IsNullOrWhiteSpace(info.ProviderPrimary))
        {
            tags.Add(info.ProviderPrimary);
        }

        var samples = info.Hosts
            .Take(4)
            .Select(static host => (host.Priority.HasValue ? host.Priority.Value + " " : string.Empty) + host.Host)
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "MX routing",
            ValueLabel = info.MxRecordExists ? info.MxRecords.Count + " route(s)" : "Missing",
            Summary = "DD analyzed MX routing, provider fingerprints, redundancy, and target quality for the domain mail path.",
            Tags = tags,
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildTransportCard(DomainOverviewInfo info)
    {
        var tags = new List<string>();
        if (info.Mtasts != null)
        {
            tags.Add(info.Mtasts.PolicyPresent ? "MTA-STS" : "No MTA-STS");
        }

        if (info.TlsRpt != null)
        {
            tags.Add(info.TlsRpt.TlsRptRecordExists ? "TLS-RPT" : "No TLS-RPT");
        }

        if (info.Bimi != null)
        {
            tags.Add(info.Bimi.BimiRecordExists ? "BIMI" : "No BIMI");
        }

        if (info.Caa != null)
        {
            tags.Add(info.Caa.ValidRecords > 0 ? "CAA " + info.Caa.ValidRecords : "No CAA");
        }

        if (info.Dane != null)
        {
            tags.Add(info.Dane.NumberOfRecords > 0 ? "DANE " + info.Dane.ValidRecordCount : "No DANE");
        }

        var samples = new List<string>();
        if (info.Mtasts != null)
        {
            samples.Add("MTA-STS: " + info.Mtasts.Summary);
        }

        if (info.TlsRpt != null)
        {
            samples.Add("TLS-RPT: " + info.TlsRpt.Summary);
        }

        if (info.Bimi != null)
        {
            samples.Add("BIMI: " + info.Bimi.Summary);
        }

        if (info.Caa != null)
        {
            samples.Add("CAA: " + info.Caa.Summary);
        }

        if (info.Dane != null)
        {
            samples.Add("DANE: " + info.Dane.Summary);
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Transport and trust policies",
            ValueLabel = tags.Count(static tag => !tag.StartsWith("No ", StringComparison.Ordinal)) + " enabled",
            Summary = "DD checked transport policy, reporting, brand indicators, certificate authority policy, and TLSA posture for mail delivery hardening.",
            Tags = tags,
            Samples = samples.Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildDnsInfrastructureCard(DomainOverviewInfo info)
    {
        var tags = new List<string>();
        if (info.Dnssec != null)
        {
            tags.Add(info.Dnssec.ChainValid ? "DNSSEC valid" : "DNSSEC issues");
        }

        if (info.Ns != null)
        {
            tags.Add(info.Ns.NsRecords.Count + " NS");
            tags.Add(info.Ns.AsnDistinctCount + " ASN");
        }

        if (info.Soa != null)
        {
            tags.Add("SOA serial " + info.Soa.SerialNumber);
        }

        var samples = new List<string>();
        if (info.Ns != null)
        {
            samples.AddRange(info.Ns.NsRecords.Take(3).Select(static value => "NS: " + value));
        }

        if (info.Soa != null)
        {
            samples.Add("Primary NS: " + info.Soa.PrimaryNameServer);
            samples.Add("Refresh: " + info.Soa.Refresh + "s");
        }

        if (info.Dnssec != null)
        {
            samples.Add("DNSSEC: chain " + (info.Dnssec.ChainValid ? "valid" : "invalid") + ", DS " + (info.Dnssec.DsMatch ? "match" : "review"));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "DNS infrastructure",
            ValueLabel = info.Dnssec?.ChainValid == true ? "Protected" : "Review needed",
            Summary = "DD used DNSSEC validation, nameserver delegation, and SOA timing to judge baseline DNS infrastructure quality.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray()
        };
    }


    public static IReadOnlyList<DomainOverviewDetailCardView> BuildWebRegistrationCards(DomainOverviewInfo? info)
    {
        if (info == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        var cards = new List<DomainOverviewDetailCardView>();
        if (info.Http != null)
        {
            cards.Add(BuildHttpCard(info.Http));
        }

        if (info.Certificate != null)
        {
            cards.Add(BuildCertificateCard(info.Certificate));
        }

        if (info.SecurityTxt != null)
        {
            cards.Add(BuildSecurityTxtCard(info.SecurityTxt));
        }

        if (info.Rdap != null)
        {
            cards.Add(BuildRdapCard(info.Rdap));
        }

        if (info.Dnsbl != null)
        {
            cards.Add(BuildDnsblCard(info.Dnsbl));
        }

        return cards;
    }

    public static IReadOnlyList<DomainExposureView> BuildExposureEntries(SubdomainsInfo? subdomains)
    {
        if (subdomains?.Subdomains == null || subdomains.Subdomains.Count == 0)
        {
            return Array.Empty<DomainExposureView>();
        }

        return subdomains.Subdomains
            .OrderByDescending(static entry => GetRiskWeight(entry))
            .ThenByDescending(static entry => entry.CertificateObservationCount)
            .ThenBy(static entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .Select(static entry => new DomainExposureView
            {
                Name = entry.Name,
                ResolutionLabel = Humanize(entry.ResolutionStatus.ToString()),
                RiskLabel = entry.SensitiveRisk == SensitiveSubdomainRisk.None ? "Standard naming" : Humanize(entry.SensitiveRisk.ToString()) + " sensitivity",
                Summary = BuildExposureSummary(entry),
                Signals = BuildExposureSignals(entry),
                Samples = BuildExposureSamples(entry)
            })
            .ToArray();
    }

    private static DomainOverviewDetailCardView BuildProviderCard(DomainOverviewInfo info)
    {
        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.MailProvider) && !string.Equals(info.MailProvider, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            samples.Add("Mail provider: " + info.MailProvider);
        }

        if (!string.IsNullOrWhiteSpace(info.DnsProvider) && !string.Equals(info.DnsProvider, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            samples.Add("DNS provider: " + info.DnsProvider);
        }

        samples.AddRange(info.Highlights
            .Where(static item => item.Contains("provider", StringComparison.OrdinalIgnoreCase))
            .Take(2));

        return new DomainOverviewDetailCardView
        {
            Title = "Provider signals",
            ValueLabel = info.DetectedApplicationCount + " app hints",
            Summary = "DD correlated DNS inventory, mail routing, and application fingerprints to infer provider posture for this domain.",
            Tags = new[]
            {
                "Mail: " + FormatProviderValue(info.MailProvider),
                "DNS: " + FormatProviderValue(info.DnsProvider)
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildEvidenceCoverageCard(DomainOverviewInfo info)
    {
        var samples = new List<string>();
        samples.AddRange(info.MailDnsChecks
            .Where(static check => check.State == AggregateCheckState.Fail || check.State == AggregateCheckState.Warning)
            .Take(2)
            .Select(static check => check.Label + ": " + check.Value));
        samples.AddRange(info.WebRegistrationChecks
            .Where(static check => check.State == AggregateCheckState.Fail || check.State == AggregateCheckState.Warning)
            .Take(2)
            .Select(static check => check.Label + ": " + check.Value));

        return new DomainOverviewDetailCardView
        {
            Title = "Evidence coverage",
            ValueLabel = (info.MailDnsChecks.Count + info.WebRegistrationChecks.Count) + " control findings",
            Summary = "DD combined mail, DNS, web, registration, and exposure checks into the domain posture shown on this page. This card summarizes how broad that evidence set was.",
            Tags = new[]
            {
                "Mail/DNS checks: " + info.MailDnsChecks.Count,
                "Web/registration checks: " + info.WebRegistrationChecks.Count,
                "Assessments: " + info.TotalAssessments
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildProviderSurfaceCard(DomainOverviewInfo info)
    {
        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.MailProvider) && !string.Equals(info.MailProvider, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            samples.Add("Mail provider: " + info.MailProvider);
        }

        if (!string.IsNullOrWhiteSpace(info.DnsProvider) && !string.Equals(info.DnsProvider, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            samples.Add("DNS provider: " + info.DnsProvider);
        }

        samples.AddRange(info.DetectedApplications
            .Where(static item => !string.IsNullOrWhiteSpace(item.Name))
            .Take(3)
            .Select(static item => item.Name + " via " + item.Source));

        return new DomainOverviewDetailCardView
        {
            Title = "Provider and app surface",
            ValueLabel = info.DetectedApplicationCount + " app hint(s)",
            Summary = "Provider, routing, and third-party application evidence all contributed to DD's view of the domain's public operating surface.",
            Tags = new[]
            {
                "Mail: " + FormatProviderValue(info.MailProvider),
                "DNS: " + FormatProviderValue(info.DnsProvider),
                "Subdomains: " + info.SubdomainCount
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildWebRegistrationSurfaceCard(DomainOverviewInfo info)
    {
        var enabledCount = 0;
        if (info.HttpReachable)
        {
            enabledCount++;
        }

        if (info.SecurityTxtPublished)
        {
            enabledCount++;
        }

        if (info.Rdap?.RecordAvailable == true)
        {
            enabledCount++;
        }

        var samples = new List<string>();
        if (info.Http != null)
        {
            samples.Add("HTTP: " + info.Http.Grade + " / " + (info.Http.HstsPresent ? "HSTS" : "No HSTS"));
        }

        if (info.Certificate != null)
        {
            samples.Add("Certificate: " + (info.Certificate.IsValid ? "valid" : "review needed"));
        }

        if (info.Rdap != null && !string.IsNullOrWhiteSpace(info.Rdap.Registrar))
        {
            samples.Add("Registrar: " + info.Rdap.Registrar);
        }

        if (info.Dnsbl != null)
        {
            samples.Add("DNSBL: " + (info.Dnsbl.HostsListed > 0 ? info.Dnsbl.HostsListed + " listed" : "clear"));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Web and registration surface",
            ValueLabel = enabledCount + " core sources available",
            Summary = "DD blended HTTP, certificate, disclosure, DNSBL, and RDAP sources to judge the outward-facing web and registration surface for this domain.",
            Tags = new[]
            {
                info.HttpReachable ? "HTTP reachable" : "HTTP offline",
                info.SecurityTxtPublished ? "Security.txt published" : "No security.txt",
                info.DaysUntilExpiration.HasValue ? "Expiry: " + FormatExpiryLabel(info.DaysUntilExpiration.Value) : "Expiry unknown"
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildExposureSurfaceCard(SubdomainsInfo subdomains)
    {
        var samples = new List<string>();
        samples.AddRange(subdomains.Highlights.Take(3));
        samples.AddRange(subdomains.Subdomains
            .OrderByDescending(static entry => GetRiskWeight(entry))
            .Take(2)
            .Select(static entry => entry.Name + ": " + BuildExposureSummary(entry)));

        return new DomainOverviewDetailCardView
        {
            Title = "Exposure surface",
            ValueLabel = subdomains.SubdomainCount + " subdomain(s)",
            Summary = "DD used discovered subdomains, naming sensitivity, resolution status, and certificate observations to judge the domain's exposure footprint.",
            Tags = new[]
            {
                "Resolving: " + subdomains.ResolvesCount,
                "High sensitivity: " + subdomains.SensitiveHighCount,
                "AI-signaled: " + subdomains.AiExposureCount
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildMailPostureCard(DomainOverviewInfo info)
    {
        var samples = info.MailDnsChecks
            .Where(static check => check.State == AggregateCheckState.Fail || check.State == AggregateCheckState.Warning)
            .Take(4)
            .Select(static check => check.Label + ": " + check.Value + " (" + check.Detail + ")")
            .ToList();

        if (samples.Count == 0)
        {
            samples.AddRange(info.MailDnsChecks
                .Take(4)
                .Select(static check => check.Label + ": " + check.Value + " (" + check.Detail + ")"));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Mail and DNS posture",
            ValueLabel = info.MailDnsChecks.Count(static check => check.State == AggregateCheckState.Pass) + " pass",
            Summary = "DD combined SPF, DKIM, DMARC, MX, transport policy, and authoritative DNS checks into the mail-security posture shown on this page.",
            Tags = info.MailDnsChecks
                .Select(static check => check.Label + " " + check.Value)
                .Take(5)
                .ToArray(),
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildWebEvidenceCard(DomainOverviewInfo info)
    {
        var samples = new List<string>();
        if (info.Http != null)
        {
            samples.AddRange(info.Http.Highlights.Take(2));
        }

        if (info.Certificate != null)
        {
            samples.AddRange(info.Certificate.Highlights.Take(2));
        }

        if (info.SecurityTxt != null)
        {
            samples.AddRange(info.SecurityTxt.Highlights.Take(1));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Web posture evidence",
            ValueLabel = info.HttpReachable ? "Grade " + info.HttpGrade : "Offline",
            Summary = "HTTP response behavior, TLS certificate posture, and disclosure controls contribute to the web-facing DD assessment for the domain.",
            Tags = BuildWebEvidenceTags(info),
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildRegistrationEvidenceCard(RdapInfo info)
    {
        var samples = new List<string>();
        samples.AddRange(info.NameServers.Take(3).Select(static value => "NS: " + value));
        samples.AddRange(info.StatusValues.Take(2).Select(static value => "Status: " + value));
        samples.AddRange(info.EventSummaries
            .Where(static item => !string.IsNullOrWhiteSpace(item.Action) && !string.IsNullOrWhiteSpace(item.Date))
            .Take(2)
            .Select(static item => item.Action + ": " + item.Date));

        return new DomainOverviewDetailCardView
        {
            Title = "Registration evidence",
            ValueLabel = info.RecordAvailable ? FormatDays(info.DaysUntilExpiration, "Available") : "Unavailable",
            Summary = info.RecordAvailable
                ? "RDAP data contributed registrar, expiry, status, and contact evidence to the DD overview."
                : "Registration evidence was not available during the DD run.",
            Tags = new[]
            {
                "Registrar: " + (string.IsNullOrWhiteSpace(info.Registrar) ? "Unknown" : info.Registrar),
                info.HasContactEntity ? "Contact entity" : "No contact entity",
                info.HasHoldStatus ? "Hold status" : "No hold status"
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildApplicationFootprintCard(DomainOverviewInfo info)
    {
        var applications = info.DetectedApplications
            .Where(static item => !string.IsNullOrWhiteSpace(item.Name))
            .Take(4)
            .Select(static item => item.Name + " via " + item.Source)
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "Application footprint evidence",
            ValueLabel = info.DetectedApplicationCount + " detected",
            Summary = "DD used DNS application fingerprints to infer third-party services and provider overlap across the domain.",
            Tags = new[]
            {
                info.DetectedApplicationCount + " application match(es)",
                info.SubdomainCount + " subdomain(s)"
            },
            Samples = applications
        };
    }

    private static DomainOverviewDetailCardView BuildExposureEvidenceCard(SubdomainsInfo subdomains)
    {
        var samples = new List<string>();
        samples.AddRange(subdomains.Highlights.Take(3));
        samples.AddRange(subdomains.Subdomains
            .Where(static item => item.SensitiveRisk != SensitiveSubdomainRisk.None)
            .Take(2)
            .Select(static item => item.Name + " (" + Humanize(item.SensitiveRisk.ToString()) + " sensitivity)"));

        return new DomainOverviewDetailCardView
        {
            Title = "Exposure evidence",
            ValueLabel = subdomains.SubdomainCount + " found",
            Summary = "Certificate transparency, resolver checks, and certificate signals drive the exposure picture in this DD overview.",
            Tags = new[]
            {
                subdomains.ResolvesCount + " resolving",
                subdomains.SensitiveHighCount + " high sensitivity",
                subdomains.AiExposureCount + " AI-signaled"
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildHttpCard(HttpInfo info)
    {
        var tags = new List<string>();
        if (info.StatusCode.HasValue)
        {
            tags.Add("Status " + info.StatusCode.Value);
        }

        if (!string.IsNullOrWhiteSpace(info.ProtocolVersion))
        {
            tags.Add(info.ProtocolVersion);
        }

        tags.Add(info.HstsPresent ? "HSTS on" : "HSTS missing");
        tags.Add(info.Http2Supported ? "HTTP/2" : "No HTTP/2");

        if (info.MissingSecurityHeaders.Count > 0)
        {
            tags.Add(info.MissingSecurityHeaders.Count + " missing headers");
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.ServerHeader))
        {
            samples.Add("Server: " + info.ServerHeader);
        }

        if (!string.IsNullOrWhiteSpace(info.ReferrerPolicy))
        {
            samples.Add("Referrer-Policy: " + info.ReferrerPolicy);
        }

        samples.AddRange(info.Highlights.Take(2));
        if (samples.Count == 0)
        {
            samples.AddRange(info.Details.Take(2));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "HTTP headers",
            ValueLabel = info.IsReachable ? "Grade " + info.Grade.ToString() : "Offline",
            Summary = info.IsReachable
                ? $"Reachable over {(string.IsNullOrWhiteSpace(info.ProtocolVersion) ? "HTTP" : info.ProtocolVersion)} with {(info.HstsPresent ? "HSTS enabled" : "no HSTS")} and {info.MissingSecurityHeaders.Count} missing security header(s)."
                : (string.IsNullOrWhiteSpace(info.FailureReason) ? "HTTP endpoint was not reachable during the DD run." : info.FailureReason),
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildCertificateCard(CertificateInfo info)
    {
        var tags = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.TlsProtocol))
        {
            tags.Add(info.TlsProtocol);
        }

        if (!string.IsNullOrWhiteSpace(info.KeyAlgorithm))
        {
            tags.Add(info.KeyAlgorithm + " " + info.KeySize);
        }

        if (info.IsSelfSigned)
        {
            tags.Add("Self-signed");
        }

        if (info.WeakKey)
        {
            tags.Add("Weak key");
        }

        if (info.OcspStaplingPresent == true)
        {
            tags.Add("OCSP stapling");
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.CertificateIssuer))
        {
            samples.Add("Issuer: " + info.CertificateIssuer);
        }

        if (!string.IsNullOrWhiteSpace(info.CertificateSubject))
        {
            samples.Add("Subject: " + info.CertificateSubject);
        }

        samples.AddRange(info.Highlights.Take(2));

        return new DomainOverviewDetailCardView
        {
            Title = "TLS certificate",
            ValueLabel = info.IsReachable ? (string.IsNullOrWhiteSpace(info.TlsProtocol) ? "Present" : info.TlsProtocol) : "Missing",
            Summary = info.IsReachable
                ? $"Certificate {(info.IsValid ? "validated" : "did not validate")} with hostname {(info.HostnameMatch ? "match" : "mismatch")} and expiry {FormatCertificateExpiry(info)}."
                : (string.IsNullOrWhiteSpace(info.FailureReason) ? "No TLS certificate was obtained for the target." : info.FailureReason),
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildSecurityTxtCard(SecurityTxtInfo info)
    {
        var tags = new List<string>
        {
            info.RecordPresent ? "Published" : "Missing"
        };

        if (info.PGPSigned)
        {
            tags.Add("PGP signed");
        }

        if (info.FallbackUsed)
        {
            tags.Add("Fallback path");
        }

        if (info.DaysUntilExpiry.HasValue)
        {
            tags.Add(FormatDays(info.DaysUntilExpiry, "Expiry unknown"));
        }

        var samples = new List<string>();
        samples.AddRange(info.ContactEmail.Take(2).Select(static value => "Contact email: " + value));
        samples.AddRange(info.ContactWebsite.Take(1).Select(static value => "Contact URL: " + value));
        samples.AddRange(info.Highlights.Take(2));

        return new DomainOverviewDetailCardView
        {
            Title = "Security.txt",
            ValueLabel = info.RecordPresent ? "Published" : "Missing",
            Summary = info.RecordPresent
                ? $"Disclosure file is {(info.RecordValid ? "valid" : "present but needs attention")} with {info.ContactEmail.Count + info.ContactWebsite.Count} contact route(s)."
                : "No security.txt disclosure policy was found.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildRdapCard(RdapInfo info)
    {
        var tags = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.Registrar))
        {
            tags.Add(info.Registrar);
        }

        if (info.HasHoldStatus)
        {
            tags.Add("Hold status");
        }

        if (info.HasContactEntity)
        {
            tags.Add("Contact entity");
        }

        if (info.NameServers.Count > 0)
        {
            tags.Add(info.NameServers.Count + " NS");
        }

        var samples = new List<string>();
        samples.AddRange(info.EventSummaries
            .Where(static item => !string.IsNullOrWhiteSpace(item.Action) && !string.IsNullOrWhiteSpace(item.Date))
            .Take(2)
            .Select(static item => item.Action + ": " + item.Date));
        samples.AddRange(info.EntitySummaries
            .Where(static item => !string.IsNullOrWhiteSpace(item.Handle))
            .Take(2)
            .Select(static item => "Entity: " + item.Handle));

        return new DomainOverviewDetailCardView
        {
            Title = "Registration",
            ValueLabel = info.RecordAvailable ? FormatDays(info.DaysUntilExpiration, "Available") : "Unavailable",
            Summary = info.RecordAvailable
                ? $"Registration data is available from {(string.IsNullOrWhiteSpace(info.Registrar) ? "the registrar" : info.Registrar)} with {info.StatusValues.Count} status value(s)."
                : "Registration data was not available during the DD run.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildDnsblCard(DnsblInfo info)
    {
        var tags = new List<string>
        {
            info.Pathways.Count + " pathway(s)",
            info.Targets.Count + " target(s)"
        };

        if (info.ProvidersWithListings > 0)
        {
            tags.Add(info.ProvidersWithListings + " provider(s) listing");
        }

        var samples = new List<string>();
        samples.AddRange(info.Listings.Take(3).Select(static item => item.Target + " via " + item.Provider));
        if (samples.Count == 0)
        {
            samples.AddRange(info.Pathways.Take(2).Select(static item => item.Label + ": " + item.TargetsChecked + " checked"));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "DNSBL footprint",
            ValueLabel = info.HostsListed > 0 ? info.HostsListed + " listed" : "Clear",
            Summary = info.HostsListed > 0
                ? $"Detected {info.HostsListed} listed host(s) across {info.ProvidersWithListings} provider(s)."
                : $"No active listings were returned across {info.ProvidersChecked} checked providers.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static IReadOnlyList<string> BuildWebEvidenceTags(DomainOverviewInfo info)
    {
        var tags = new List<string>
        {
            info.HttpReachable ? "HTTP reachable" : "HTTP offline"
        };

        if (info.Certificate != null)
        {
            tags.Add(info.Certificate.IsValid ? "TLS valid" : "TLS issues");
        }

        if (info.SecurityTxt != null)
        {
            tags.Add(info.SecurityTxt.RecordPresent ? "security.txt published" : "security.txt missing");
        }

        return tags;
    }

    private static string BuildExposureSummary(SubdomainDiscoveryEntry entry)
    {
        var builder = new StringBuilder();
        builder.Append(Humanize(entry.ResolutionStatus.ToString()));
        builder.Append(" subdomain");

        if (entry.CertificateObservationCount > 0)
        {
            builder.Append(" with ");
            builder.Append(entry.CertificateObservationCount);
            builder.Append(" CT observation(s)");
        }

        if (entry.SensitiveRisk != SensitiveSubdomainRisk.None)
        {
            builder.Append(" and ");
            builder.Append(Humanize(entry.SensitiveRisk.ToString()).ToLowerInvariant());
            builder.Append(" sensitive naming");
        }

        if (!string.IsNullOrWhiteSpace(entry.LatestCertificateIssuer))
        {
            builder.Append(". Latest issuer: ");
            builder.Append(entry.LatestCertificateIssuer);
        }

        return builder.ToString();
    }

    private static IReadOnlyList<string> BuildExposureSignals(SubdomainDiscoveryEntry entry)
    {
        var signals = new List<string>
        {
            Humanize(entry.ResolutionStatus.ToString())
        };

        if (entry.SensitiveRisk != SensitiveSubdomainRisk.None)
        {
            signals.Add(Humanize(entry.SensitiveRisk.ToString()) + " sensitivity");
        }

        if (entry.LatestCertificateIsSelfSigned == true)
        {
            signals.Add("Self-signed cert");
        }

        if (entry.LatestCertificateWeakKey == true)
        {
            signals.Add("Weak cert key");
        }

        if (entry.AiSignals.Count > 0)
        {
            signals.Add("AI signals");
        }

        if (entry.CtSources.Count > 0)
        {
            signals.Add(entry.CtSources.Count + " CT source(s)");
        }

        return signals;
    }

    private static IReadOnlyList<string> BuildExposureSamples(SubdomainDiscoveryEntry entry)
    {
        var samples = new List<string>();
        samples.AddRange(entry.ARecords.Take(2).Select(static value => "A: " + value));
        samples.AddRange(entry.AaaaRecords.Take(2).Select(static value => "AAAA: " + value));
        samples.AddRange(entry.SensitiveSignals.Take(2).Select(static value => "Sensitive: " + value));
        samples.AddRange(entry.AiSignals.Take(2).Select(static value => "AI: " + value));

        if (!string.IsNullOrWhiteSpace(entry.LatestCertificateAuthenticationProfile))
        {
            samples.Add("Auth profile: " + entry.LatestCertificateAuthenticationProfile);
        }

        samples.AddRange(entry.CtSources.Take(2).Select(static value => "CT source: " + value));
        return samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray();
    }

    private static int GetRiskWeight(SubdomainDiscoveryEntry entry)
    {
        var weight = entry.SensitiveRisk switch
        {
            SensitiveSubdomainRisk.High => 40,
            SensitiveSubdomainRisk.Moderate => 20,
            _ => 0
        };

        if (entry.ResolutionStatus == SubdomainResolutionStatus.Resolves)
        {
            weight += 10;
        }

        if (entry.LatestCertificateWeakKey == true)
        {
            weight += 5;
        }

        if (entry.LatestCertificateIsSelfSigned == true)
        {
            weight += 5;
        }

        if (entry.AiSignals.Count > 0)
        {
            weight += 3;
        }

        return weight;
    }

    private static string FormatCertificateExpiry(CertificateInfo info)
    {
        if (info.IsExpired)
        {
            return "expired";
        }

        if (info.DaysToExpire > 0)
        {
            return info.DaysToExpire + " days";
        }

        if (info.ValidTo.HasValue)
        {
            return info.ValidTo.Value.ToString("yyyy-MM-dd");
        }

        return "unknown";
    }

    private static string FormatDays(int? days, string fallback)
    {
        if (!days.HasValue)
        {
            return fallback;
        }

        return days.Value >= 0 ? days.Value + " days" : "Expired";
    }

    private static string FormatProviderValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) || string.Equals(value, "Unknown", StringComparison.OrdinalIgnoreCase)
            ? "Unknown"
            : value;
    }

    private static string FormatExpiryLabel(int daysUntilExpiration)
    {
        if (daysUntilExpiration < 0)
        {
            return "expired";
        }

        if (daysUntilExpiration == 0)
        {
            return "expires today";
        }

        if (daysUntilExpiration == 1)
        {
            return "1 day";
        }

        return daysUntilExpiration + " days";
    }

    private static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value.Substring(0, maxLength - 1) + "…";
    }

    private static string Humanize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length + 8);
        builder.Append(value[0]);

        for (var i = 1; i < value.Length; i++)
        {
            var current = value[i];
            var previous = value[i - 1];
            if (char.IsUpper(current) && (char.IsLower(previous) || char.IsDigit(previous)))
            {
                builder.Append(' ');
            }
            else if (char.IsDigit(current) && char.IsLetter(previous))
            {
                builder.Append(' ');
            }

            builder.Append(current);
        }

        return builder.ToString();
    }
}

public sealed class DomainOverviewDetailCardView
{
    public string Title { get; init; } = string.Empty;
    public string ValueLabel { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Samples { get; init; } = Array.Empty<string>();
}

internal sealed class DomainExposureView
{
    public string Name { get; init; } = string.Empty;
    public string ResolutionLabel { get; init; } = string.Empty;
    public string RiskLabel { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Signals { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Samples { get; init; } = Array.Empty<string>();
}
