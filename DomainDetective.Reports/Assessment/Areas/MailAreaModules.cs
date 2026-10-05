using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Views;
using static DomainDetective.Reports.AreaText;

namespace DomainDetective.Reports;

/// <summary>SPF: lookup budget, how the record ends, what it authorizes.</summary>
internal sealed class SpfAreaModule : IAssessmentAreaModule {
    private const int LookupLimit = 10;

    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.SPF };

    public bool Describe(CheckAssessment check, int maxRows) {
        SpfRecordInfo? spf = check.Sources.OfType<SpfRecordInfo>().FirstOrDefault();
        if (spf == null) return false;
        if (!spf.SpfRecordExists) {
            // A failed lookup says nothing about the record; calling it missing would raise a false alarm.
            check.Metrics.Add(spf.DnsQueryFailed
                ? Metric("Record", "Unknown", MetricState.Warning, "the DNS lookup failed")
                : Metric("Record", "Missing", MetricState.Error, "anyone can send as this domain"));
            return true;
        }

        MetricState lookups = spf.ExceedsDnsLookups ? MetricState.Error : spf.DnsLookupsCount >= LookupLimit - 2 ? MetricState.Warning : MetricState.Good;
        check.Metrics.Add(Metric("DNS lookups", $"{N(spf.DnsLookupsCount)} / {N(LookupLimit)}", lookups, "limit set by RFC 7208"));
        check.Metrics.Add(Metric("Ends with", AllLabel(spf.AllMechanism), AllState(spf.AllMechanism)));
        check.Metrics.Add(Metric("Includes", N(spf.Includes.Count)));
        if (spf.FlattenedUniqueIps.Count > 0) check.Metrics.Add(Metric("Authorized addresses", N(spf.FlattenedUniqueIps.Count), note: "after resolving includes"));
        bool tooLong = spf.ExceedsCharacterLimit || spf.ExceedsTotalCharacterLimit;
        check.Metrics.Add(Metric("Record length", N(spf.RecordLength) + " chars", tooLong ? MetricState.Warning : MetricState.Neutral));

        if (spf.MultipleSpfRecords) Fact(check, "Multiple SPF records", "Yes — receivers treat this as a permanent error");
        Fact(check, "Redirect", spf.RedirectValue);
        Fact(check, "Explanation (exp)", spf.ExpValue);
        if (spf.ProviderCounts.Count > 0) {
            Fact(check, "Sending services", string.Join(", ", spf.ProviderCounts.OrderByDescending(static p => p.Value).Select(static p => p.Value > 1 ? $"{p.Key} ({N(p.Value)})" : p.Key)));
        }
        if (spf.HasPtrType) Fact(check, "Uses ptr", "Yes — deprecated and slow");
        if (spf.HasNullLookups) Fact(check, "Void lookups", "Yes — an include or a name resolves to nothing");
        if (spf.CycleDetected) Fact(check, "Include loop", spf.CyclePath ?? "Yes");
        if (spf.UnknownMechanisms.Count > 0) Fact(check, "Unknown mechanisms", string.Join(", ", spf.UnknownMechanisms));

        Code(check, "SPF record", spf.SpfRecord);
        Table(check, "Mechanisms", new[] { "Result", "Mechanism", "Value", "Service", "Via" },
            spf.Mechanisms.Select(static m => (IReadOnlyList<string?>)new[] {
                NullIfEmpty(m.PrefixDesc) ?? m.Prefix,
                m.Type,
                m.Value,
                m.Provider,
                m.Depth > 0 ? m.SourceDomain : null
            }), maxRows);
        // Resolved addresses rotate (cloud mail and web hosts), so they are evidence of today, not configuration.
        List(check, "Addresses the record authorizes", spf.FlattenedUniqueIps.OrderBy(static ip => ip, StringComparer.Ordinal), maxRows, isVolatile: true);
        List(check, "Addresses authorized more than once", spf.FlattenedDuplicateIps.OrderBy(static ip => ip, StringComparer.Ordinal), maxRows, isVolatile: true);
        return true;
    }

    private static string AllLabel(string? all) => Normalize(all) switch {
        "-all" => "-all (fail)",
        "~all" => "~all (soft fail)",
        "?all" => "?all (neutral)",
        "+all" or "all" => "+all (allows anyone)",
        _ => "No all mechanism"
    };

    private static MetricState AllState(string? all) => Normalize(all) switch {
        "-all" => MetricState.Good,
        "~all" => MetricState.Neutral,
        "+all" or "all" => MetricState.Error,
        _ => MetricState.Warning
    };

    private static string Normalize(string? all) => (all ?? string.Empty).Trim().ToLowerInvariant();
}

/// <summary>DMARC: policy strength, coverage, where reports go.</summary>
internal sealed class DmarcAreaModule : IAssessmentAreaModule {
    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.DMARC };

    public bool Describe(CheckAssessment check, int maxRows) {
        DmarcRecordInfo? dmarc = check.Sources.OfType<DmarcRecordInfo>().FirstOrDefault();
        if (dmarc == null) return false;
        if (!dmarc.DmarcRecordExists) {
            check.Metrics.Add(dmarc.DnsQueryFailed
                ? Metric("Record", "Unknown", MetricState.Warning, "the DNS lookup failed")
                : Metric("Record", "Missing", MetricState.Error, "spoofed mail is not rejected"));
            return true;
        }

        string policy = PolicyWord(dmarc.Policy);
        check.Metrics.Add(Metric("Policy", string.IsNullOrEmpty(policy) ? "Invalid" : policy, PolicyState(policy)));
        // The analysis reports an inherited subdomain policy as "reject (inherited)".
        string subText = Lower(dmarc.SubPolicy);
        string subPolicy = PolicyWord(dmarc.SubPolicy);
        bool inherited = subPolicy.Length == 0 || subText.IndexOf("inherit", StringComparison.Ordinal) >= 0;
        string effectiveSub = subPolicy.Length == 0 ? policy : subPolicy;
        check.Metrics.Add(Metric("Subdomains", effectiveSub.Length == 0 ? "Invalid" : effectiveSub + (inherited ? " (inherited)" : string.Empty), PolicyState(effectiveSub)));
        int pct = dmarc.Pct ?? 100;
        check.Metrics.Add(Metric("Applied to", pct.ToString(CultureInfo.InvariantCulture) + "%", pct >= 100 ? MetricState.Good : MetricState.Warning, "of failing mail"));
        int aggregate = dmarc.MailtoRua.Count + dmarc.HttpRua.Count;
        check.Metrics.Add(Metric("Aggregate reports", aggregate == 0 ? "None" : N(aggregate) + (aggregate == 1 ? " address" : " addresses"), aggregate == 0 ? MetricState.Warning : MetricState.Good));
        check.Metrics.Add(Metric("Alignment", $"DKIM {Alignment(dmarc.DkimAlignment)} · SPF {Alignment(dmarc.SpfAlignment)}"));

        Fact(check, "Non-existent subdomains (np)", dmarc.NonexistentPolicy);
        Fact(check, "Failure reporting (fo)", dmarc.ReportFeedback);
        Fact(check, "Recommended next step", dmarc.PolicyRecommendation);
        if (dmarc.MultipleRecords) Fact(check, "Multiple DMARC records", "Yes — receivers ignore DMARC for this domain");
        if (dmarc.DeprecatedTags.Count > 0) Fact(check, "Deprecated tags", string.Join(", ", dmarc.DeprecatedTags));
        if (dmarc.UnknownTags.Count > 0) Fact(check, "Unknown tags", string.Join(", ", dmarc.UnknownTags));

        Code(check, "DMARC record", dmarc.DmarcRecord);
        var destinations = new List<IReadOnlyList<string?>>();
        void Add(IEnumerable<string> addresses, string kind) {
            foreach (string address in addresses) destinations.Add(new[] { kind, address, Authorization(dmarc, address) });
        }
        Add(dmarc.MailtoRua.Concat(dmarc.HttpRua), "Aggregate (rua)");
        Add(dmarc.MailtoRuf.Concat(dmarc.HttpRuf), "Failure (ruf)");
        Table(check, "Report destinations", new[] { "Reports", "Address", "External authorization" }, destinations, maxRows);
        return true;
    }

    // Reports sent to another organization need that organization to publish an authorization record (RFC 7489 7.1).
    private static string Authorization(DmarcRecordInfo dmarc, string address) {
        string? host = AddressDomain(address);
        if (host == null) return "Unknown";
        if (SameOrganization(host, dmarc.Subject)) return "Not needed";
        if (dmarc.UnauthorizedExternalReportDomains.Any(d => string.Equals(d, host, StringComparison.OrdinalIgnoreCase))) return "Missing";
        return dmarc.ExternalReportAuthorization.TryGetValue(host, out bool authorized) ? authorized ? "Published" : "Missing" : "Not checked";
    }

    private static MetricState PolicyState(string policy) => policy switch {
        "reject" or "quarantine" => MetricState.Good,
        "none" => MetricState.Warning,
        _ => MetricState.Error
    };

    private static string Alignment(string? mode) => Lower(mode) switch {
        "s" or "strict" => "strict",
        _ => "relaxed"
    };

    private static string Lower(string? value) => (value ?? string.Empty).Trim().ToLowerInvariant();

    private static string PolicyWord(string? value) {
        string text = Lower(value);
        int end = text.IndexOfAny(new[] { ' ', '(' });
        return end < 0 ? text : text.Substring(0, end);
    }
}

/// <summary>DKIM: selectors found and the state of their keys.</summary>
internal sealed class DkimAreaModule : IAssessmentAreaModule {
    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.DKIM };

    public bool Describe(CheckAssessment check, int maxRows) {
        List<DkimRecordInfo> selectors = check.Sources.OfType<DkimRecordInfo>().ToList();
        if (selectors.Count == 0) return false;
        List<DkimRecordInfo> found = selectors.Where(static s => s.DkimRecordExists).ToList();
        int weak = found.Count(static s => s.WeakKey || !s.ValidKeyLength);
        int old = found.Count(static s => s.OldKey);
        int invalid = found.Count(static s => !s.ValidPublicKey || !s.StartsCorrectly);
        int testing = found.Count(static s => (s.Flags ?? string.Empty).IndexOf('y') >= 0);

        // DomainDetective reports only the selectors it found unless asked to include missing ones; the note is shown
        // only when the tried selectors are known.
        string? tried = selectors.Count > found.Count ? $"of {N(selectors.Count)} checked" : null;
        check.Metrics.Add(Metric("Selectors found", N(found.Count), found.Count == 0 ? MetricState.Warning : MetricState.Good, tried));
        check.Metrics.Add(Metric("Weak keys", N(weak), weak > 0 ? MetricState.Warning : found.Count > 0 ? MetricState.Good : MetricState.Neutral));
        check.Metrics.Add(Metric("Invalid records", N(invalid), invalid > 0 ? MetricState.Error : found.Count > 0 ? MetricState.Good : MetricState.Neutral));
        if (old > 0) check.Metrics.Add(Metric("Keys not rotated", N(old), MetricState.Warning));
        if (testing > 0) check.Metrics.Add(Metric("In testing mode", N(testing), MetricState.Warning, "t=y"));

        Table(check, "Selectors", new[] { "Selector", "Key", "Created", "Flags", "Notes" },
            found.Select(static s => (IReadOnlyList<string?>)new[] {
                s.Selector,
                KeyLabel(s),
                s.CreationDate.HasValue ? Day(s.CreationDate.Value) : null,
                NullIfEmpty(s.Flags),
                string.Join(", ", Notes(s))
            }), maxRows);
        List(check, "Selectors checked without a record", selectors.Where(static s => !s.DkimRecordExists).Select(static s => s.Selector), maxRows);
        return true;
    }

    private static string KeyLabel(DkimRecordInfo s) {
        string type = string.IsNullOrWhiteSpace(s.KeyType) ? "rsa" : s.KeyType.Trim();
        return s.KeyLength > 0 ? $"{type.ToUpperInvariant()} {N(s.KeyLength)}" : type.ToUpperInvariant();
    }

    private static IEnumerable<string> Notes(DkimRecordInfo s) {
        if (!s.ValidPublicKey || !s.StartsCorrectly) yield return "invalid record";
        if (s.WeakKey || !s.ValidKeyLength) yield return "weak key";
        if (s.OldKey) yield return "old key";
        if (s.DeprecatedTags.Count > 0) yield return "deprecated tags: " + string.Join(" ", s.DeprecatedTags);
    }
}

/// <summary>MX: who receives mail, redundancy and reachability.</summary>
internal sealed class MxAreaModule : IAssessmentAreaModule {
    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.MX };

    public bool Describe(CheckAssessment check, int maxRows) {
        MxInfo? mx = check.Sources.OfType<MxInfo>().FirstOrDefault();
        if (mx == null) return false;
        if (mx.HasNullMx) {
            check.Metrics.Add(Metric("Mail", "Not accepted", MetricState.Neutral, "null MX published"));
            return true;
        }
        if (!mx.MxRecordExists) {
            check.Metrics.Add(Metric("Mail servers", "None", MetricState.Error, "mail cannot be delivered"));
            return true;
        }

        check.Metrics.Add(Metric("Mail servers", N(mx.Hosts.Count > 0 ? mx.Hosts.Count : mx.MxRecords.Count)));
        bool singleOk = !mx.HasBackupServers && mx.PrimaryProviderSingleMxOk;
        check.Metrics.Add(Metric("Backup server", mx.HasBackupServers ? "Yes" : "No", mx.HasBackupServers || singleOk ? MetricState.Good : MetricState.Neutral, singleOk ? "not needed for this provider" : null));
        check.Metrics.Add(Metric("IPv6", mx.Ipv6Supported ? "Yes" : "No", mx.Ipv6Supported ? MetricState.Good : MetricState.Neutral));
        if (!string.IsNullOrWhiteSpace(mx.ProviderPrimary)) check.Metrics.Add(Metric("Provider", mx.ProviderPrimary!.Trim()));

        if (mx.ProviderGateways.Count > 0) Fact(check, "Gateways", string.Join(", ", mx.ProviderGateways));
        if (mx.PointsToCname) Fact(check, "Points to a CNAME", "Yes — not allowed for MX targets");
        if (mx.PointsToIpAddress) Fact(check, "Points to an IP address", "Yes — MX must name a host");
        if (mx.PointsToNonExistentDomain) Fact(check, "Points to a missing name", "Yes");
        if (mx.PointsToDomainWithoutAOrAaaaRecord) Fact(check, "Host without an address", "Yes");
        if (!mx.MxRrsetConsistentAcrossNs) Fact(check, "Same answer from every name server", "No");

        // TTLs are left out: a caching resolver reports the time remaining, which differs on every run.
        Table(check, "Mail servers", new[] { "Priority", "Host" },
            mx.Hosts.OrderBy(static h => h.Priority ?? int.MaxValue).ThenBy(static h => h.Host, StringComparer.OrdinalIgnoreCase).Select(static h => (IReadOnlyList<string?>)new[] {
                h.Priority?.ToString(CultureInfo.InvariantCulture),
                h.Host
            }), maxRows);
        return true;
    }
}

/// <summary>Mail transport TLS (SMTP, IMAP, POP3): encryption and certificates per server.</summary>
internal sealed class MailTlsAreaModule : IAssessmentAreaModule {
    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS };

    public bool Describe(CheckAssessment check, int maxRows) {
        List<MailTlsServerInfo> servers = check.Sources.OfType<MailTlsInfo>().SelectMany(static v => v.Servers).ToList();
        if (servers.Count == 0) return false;
        int tls = servers.Count(static s => !string.IsNullOrWhiteSpace(s.Protocol));
        int certificateProblems = servers.Count(static s => !s.CertificateValid || !s.ChainValid || !s.HostnameMatch || s.IsExpired);
        int tls13 = servers.Count(static s => s.SupportsTls13 || s.Tls13Used);
        MailTlsServerInfo? soonest = servers.Where(static s => !string.IsNullOrWhiteSpace(s.Protocol)).OrderBy(static s => s.DaysToExpire).FirstOrDefault();

        check.Metrics.Add(Metric("Encrypted", $"{N(tls)} of {N(servers.Count)}", tls == servers.Count ? MetricState.Good : MetricState.Error, "servers negotiating TLS"));
        check.Metrics.Add(Metric("Certificate problems", N(certificateProblems), certificateProblems > 0 ? MetricState.Error : MetricState.Good));
        check.Metrics.Add(Metric("TLS 1.3", $"{N(tls13)} of {N(servers.Count)}", tls13 == servers.Count ? MetricState.Good : MetricState.Neutral));
        if (soonest != null) {
            DateTime? expires = soonest.ValidTo ?? soonest.CertificateNotAfter;
            int days = soonest.DaysToExpire;
            check.Metrics.Add(Metric("Next certificate expiry", expires.HasValue ? Day(expires.Value) : N(days) + " days", days < 0 ? MetricState.Error : days <= 14 ? MetricState.Warning : MetricState.Good));
        }

        Table(check, "Servers", new[] { "Server", "Port", "Address", "Protocol", "Cipher", "Certificate", "Expires" },
            servers.Select(static s => (IReadOnlyList<string?>)new[] {
                s.HostName,
                s.Port.ToString(CultureInfo.InvariantCulture),
                s.RemoteAddress ?? s.ConnectAddress,
                NullIfEmpty(s.Protocol) ?? "no TLS",
                NullIfEmpty(s.CipherSuite),
                CertificateState(s),
                string.IsNullOrWhiteSpace(s.Protocol) || !(s.ValidTo ?? s.CertificateNotAfter).HasValue ? null : Day((s.ValidTo ?? s.CertificateNotAfter)!.Value)
            }), maxRows);
        return true;
    }

    private static string CertificateState(MailTlsServerInfo s) {
        if (string.IsNullOrWhiteSpace(s.Protocol)) return string.Empty;
        var problems = new List<string>();
        if (s.IsExpired) problems.Add("expired");
        if (!s.ChainValid) problems.Add("untrusted chain");
        if (!s.HostnameMatch) problems.Add("name mismatch");
        if (!s.CertificateValid && problems.Count == 0) problems.Add("invalid");
        return problems.Count == 0 ? "valid" : string.Join(", ", problems);
    }
}

/// <summary>MTA-STS: whether TLS to the MX hosts is enforced and covers them all.</summary>
internal sealed class MtaStsAreaModule : IAssessmentAreaModule {
    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.MTASTS };

    public bool Describe(CheckAssessment check, int maxRows) {
        MtastsInfo? sts = check.Sources.OfType<MtastsInfo>().FirstOrDefault();
        if (sts == null) return false;
        if (!sts.DnsRecordPresent) {
            check.Metrics.Add(Metric("Policy", "Not published", MetricState.Warning, "senders may deliver without TLS"));
            return true;
        }

        string mode = (sts.Mode ?? string.Empty).Trim().ToLowerInvariant();
        MetricState modeState = !sts.PolicyValid ? MetricState.Error : mode == "enforce" ? MetricState.Good : MetricState.Warning;
        check.Metrics.Add(Metric("Mode", sts.PolicyValid && mode.Length > 0 ? mode : "invalid policy", modeState));
        if (sts.MaxAge > 0) {
            double days = sts.MaxAge / 86400d;
            check.Metrics.Add(Metric("Cached for", days >= 1 ? N((int)Math.Round(days)) + " days" : N(sts.MaxAge) + " s", days >= 7 ? MetricState.Good : MetricState.Warning, "max_age"));
        }
        if (sts.HasMx) check.Metrics.Add(Metric("MX covered", sts.MxAligned ? "All" : $"{N(sts.MissingMxFromPolicy.Length)} missing", sts.MxAligned ? MetricState.Good : MetricState.Error));

        Fact(check, "Policy id", sts.PolicyId);
        if (sts.PolicyFetchSkipped) Fact(check, "Policy file", "Not fetched");
        Code(check, "Policy file", sts.PolicyText);
        List(check, "MX patterns in the policy", sts.MxPatterns, maxRows);
        List(check, "MX hosts the policy does not cover", sts.MissingMxFromPolicy, maxRows);
        return true;
    }
}

/// <summary>TLS-RPT: whether TLS delivery failures are reported, and where.</summary>
internal sealed class TlsRptAreaModule : IAssessmentAreaModule {
    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.TLSRPT };

    public bool Describe(CheckAssessment check, int maxRows) {
        TlsRptInfo? rpt = check.Sources.OfType<TlsRptInfo>().FirstOrDefault();
        if (rpt == null) return false;
        if (!rpt.TlsRptRecordExists) {
            check.Metrics.Add(Metric("Record", "Not published", MetricState.Warning, "TLS delivery failures go unreported"));
            return true;
        }

        int destinations = rpt.MailtoRua.Count + rpt.HttpRua.Count;
        check.Metrics.Add(Metric("Report addresses", N(destinations), destinations > 0 ? MetricState.Good : MetricState.Error));
        if (rpt.InvalidRua.Count > 0) check.Metrics.Add(Metric("Invalid addresses", N(rpt.InvalidRua.Count), MetricState.Error));
        if (rpt.MultipleRecords) Fact(check, "Multiple TLS-RPT records", "Yes — reporters ignore the policy");
        if (rpt.UnknownTags.Count > 0) Fact(check, "Unknown tags", string.Join(", ", rpt.UnknownTags));

        Code(check, "TLS-RPT record", rpt.TlsRptRecord);
        List(check, "Report addresses", rpt.MailtoRua.Concat(rpt.HttpRua), maxRows);
        List(check, "Invalid report addresses", rpt.InvalidRua, maxRows);
        return true;
    }
}

/// <summary>BIMI: logo and verified mark certificate.</summary>
internal sealed class BimiAreaModule : IAssessmentAreaModule {
    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.BIMI };

    public bool Describe(CheckAssessment check, int maxRows) {
        BimiRecordInfo? bimi = check.Sources.OfType<BimiRecordInfo>().FirstOrDefault();
        if (bimi == null) return false;
        if (!bimi.BimiRecordExists) {
            check.Metrics.Add(Metric("Record", "Not published", MetricState.Neutral, "optional; shows the brand logo in supporting inboxes"));
            return true;
        }
        if (bimi.DeclinedToPublish) {
            check.Metrics.Add(Metric("Record", "Declined to publish", MetricState.Neutral));
            return true;
        }

        bool logo = bimi.SvgFetched && bimi.SvgValid;
        check.Metrics.Add(Metric("Logo", logo ? "Valid" : bimi.SvgFetched ? "Invalid" : "Not reachable", logo ? MetricState.Good : MetricState.Error));
        bool hasVmc = !string.IsNullOrWhiteSpace(bimi.Authority);
        check.Metrics.Add(Metric("Mark certificate", !hasVmc ? "None" : bimi.ValidVmc ? "Valid" : "Invalid", !hasVmc ? MetricState.Neutral : bimi.ValidVmc ? MetricState.Good : MetricState.Error, hasVmc ? null : "required by Gmail and Apple Mail"));
        if (bimi.VmcNotAfter.HasValue) {
            int days = (int)Math.Floor((bimi.VmcNotAfter.Value.ToUniversalTime() - DateTime.UtcNow).TotalDays);
            check.Metrics.Add(Metric("Certificate expires", Day(bimi.VmcNotAfter.Value), days < 0 ? MetricState.Error : days <= 30 ? MetricState.Warning : MetricState.Good));
        }

        Fact(check, "Logo location", bimi.Location);
        Fact(check, "Certificate location", bimi.Authority);
        Fact(check, "Logo problem", bimi.SvgInvalidReason);
        Fact(check, "Certificate subject", bimi.VmcSubject);
        Fact(check, "Certificate issuer", bimi.VmcIssuer);
        Fact(check, "Problem", bimi.FailureReason);
        Code(check, "BIMI record", bimi.BimiRecord);
        return true;
    }
}
