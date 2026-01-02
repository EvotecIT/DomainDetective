using DomainDetective.Helpers;
using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>Indicates where an IP address was discovered.</summary>
public enum IpEnrichmentSourceKind
{
    Unknown = 0,
    Apex = 1,
    Mx = 2,
    Ns = 3,
    Custom = 4
}

/// <summary>Coarse IP address family for reporting.</summary>
public enum IpAddressFamilyKind
{
    Unknown = 0,
    IPv4 = 1,
    IPv6 = 2
}

/// <summary>Input source describing a discovered IP address.</summary>
public sealed class IpEnrichmentSource
{
    public string IpAddress { get; init; } = string.Empty;
    public string SourceHost { get; init; } = string.Empty;
    public IpEnrichmentSourceKind SourceKind { get; init; } = IpEnrichmentSourceKind.Unknown;
}

/// <summary>Enriched IP row (source + rDNS + RDAP + geo hints).</summary>
public sealed class IpEnrichmentRow
{
    public string IpAddress { get; init; } = string.Empty;
    public IpAddressFamilyKind AddressFamily { get; init; } = IpAddressFamilyKind.Unknown;
    public IpEnrichmentSourceKind SourceKind { get; init; } = IpEnrichmentSourceKind.Unknown;
    public string SourceHost { get; init; } = string.Empty;
    public string Ptr { get; init; } = string.Empty;
    public string PtrRecords { get; init; } = string.Empty;
    public int? Asn { get; init; }
    public string AsName { get; init; } = string.Empty;
    public string Cidr { get; init; } = string.Empty;
    public string Country { get; init; } = string.Empty;
    public string Region { get; init; } = string.Empty;
}

/// <summary>
/// Enriches discovered IP addresses with reverse DNS (PTR), RDAP network hints (CIDR/country/org),
/// and offline GeoIP hints (when available).
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class IpEnrichmentAnalysis : IHasAssessments
{
    private static readonly GeoIpAnalysis _geo = new GeoIpAnalysis();
    private static int _geoLoaded;

    /// <summary>Domain being analyzed.</summary>
    public string? Subject { get; private set; }

    /// <summary>DNS client configuration.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Optional override for DNS queries (used by tests).</summary>
    public Func<string, DnsRecordType, CancellationToken, Task<DnsAnswer[]>>? QueryOverride { get; set; }

    /// <summary>RDAP client used for IP lookups.</summary>
    public RdapClient RdapClient { get; set; } = new();

    /// <summary>Optional override for RDAP IP lookups (used by tests/offline callers).</summary>
    public Func<string, CancellationToken, Task<RdapIpNetwork?>>? RdapQueryOverride { get; set; }

    /// <summary>When true, resolves MX host A/AAAA and includes in enrichment.</summary>
    public bool IncludeMxHostAddresses { get; set; } = true;

    /// <summary>When true, resolves NS host A/AAAA and includes in enrichment.</summary>
    public bool IncludeNsHostAddresses { get; set; } = true;

    /// <summary>Maximum number of MX/NS hosts to resolve (per kind).</summary>
    public int MaxHostsPerKind { get; set; } = 20;

    /// <summary>Maximum number of unique IPs to enrich (caps processing for very large estates).</summary>
    public int MaxUniqueIpsToEnrich { get; set; } = 200;

    /// <summary>Maximum concurrent enrichment operations.</summary>
    public int MaxParallelism { get; set; } = 8;

    /// <summary>True when processing was capped to protect performance.</summary>
    public bool ResultsCapped { get; private set; }

    /// <summary>True when enrichment completed successfully (even if partial data was returned).</summary>
    public bool QuerySucceeded { get; private set; }

    /// <summary>If <see cref="QuerySucceeded"/> is false, this may contain a short reason.</summary>
    public string? FailureReason { get; private set; }

    /// <summary>Unique IP count enriched.</summary>
    public int UniqueIpCount { get; private set; }

    /// <summary>Total row count produced (may include duplicates when the same IP appears from multiple sources).</summary>
    public int RowCount { get; private set; }

    /// <summary>Distinct ASN count (best-effort).</summary>
    public int DistinctAsnCount { get; private set; }

    /// <summary>Distinct country count (best-effort).</summary>
    public int DistinctCountryCount { get; private set; }

    /// <summary>ASN → count (unique IPs).</summary>
    public IReadOnlyDictionary<int, int> AsnCounts { get; private set; } = new Dictionary<int, int>();

    /// <summary>Country → count (unique IPs).</summary>
    public IReadOnlyDictionary<string, int> CountryCounts { get; private set; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Enriched rows.</summary>
    public IReadOnlyList<IpEnrichmentRow> Rows { get; private set; } = Array.Empty<IpEnrichmentRow>();

    /// <summary>Relevant standards for IP enrichment.</summary>
    public IReadOnlyList<StandardReference> References => new[]
    {
        new StandardReference { Title = "DNS - Implementation and Specification", Reference = "RFC 1035", Url = "https://datatracker.ietf.org/doc/html/rfc1035" },
        new StandardReference { Title = "Reverse DNS in IN-ADDR.ARPA", Reference = "RFC 1035", Url = "https://datatracker.ietf.org/doc/html/rfc1035" },
        new StandardReference { Title = "Registration Data Access Protocol (RDAP)", Reference = "RFC 7482", Url = "https://datatracker.ietf.org/doc/html/rfc7482" }
    };

    /// <summary>Assessment collection for report-friendly output.</summary>
    public List<Assessment> Assessments { get; } = new();

    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    private static void EnsureGeoLoaded()
    {
        if (Interlocked.Exchange(ref _geoLoaded, 1) == 0)
        {
            try { _geo.LoadBuiltinDatabase(clearExisting: true); } catch { }
        }
    }

    /// <summary>
    /// Performs IP enrichment for the specified <paramref name="domain"/> and optional additional IP addresses.
    /// </summary>
    public async Task AnalyzeAsync(
        string domain,
        IEnumerable<string>? additionalIpAddresses = null,
        InternalLogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        Reset();
        Subject = DomainHelper.ValidateIdn(domain);
        EnsureGeoLoaded();

        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "IP Enrichment", target: Subject) : null;

        var rawSources = new List<IpEnrichmentSource>(64);
        try
        {
            await AddApexSourcesAsync(Subject!, rawSources, cancellationToken).ConfigureAwait(false);
            if (IncludeMxHostAddresses)
            {
                await AddHostSourcesAsync(Subject!, DnsRecordType.MX, IpEnrichmentSourceKind.Mx, rawSources, cancellationToken).ConfigureAwait(false);
            }
            if (IncludeNsHostAddresses)
            {
                await AddHostSourcesAsync(Subject!, DnsRecordType.NS, IpEnrichmentSourceKind.Ns, rawSources, cancellationToken).ConfigureAwait(false);
            }

            if (additionalIpAddresses != null)
            {
                foreach (var ip in additionalIpAddresses)
                {
                    if (string.IsNullOrWhiteSpace(ip)) continue;
                    rawSources.Add(new IpEnrichmentSource
                    {
                        IpAddress = ip.Trim(),
                        SourceHost = "(input)",
                        SourceKind = IpEnrichmentSourceKind.Custom
                    });
                }
            }
        }
        catch (Exception ex)
        {
            QuerySucceeded = false;
            FailureReason = ex.Message;
            logger?.WriteErrorCode(IpEnrichmentCodes.DnsQueryFailed, "IP enrichment discovery failed: {0}", ex.Message);
            return;
        }

        var normalized = NormalizeAndDedupeSources(rawSources);
        if (normalized.Count == 0)
        {
            QuerySucceeded = true;
            UniqueIpCount = 0;
            RowCount = 0;
            logger?.WriteWarningCode(IpEnrichmentCodes.NoIpsFound, "No IP addresses found to enrich.");
            Rows = Array.Empty<IpEnrichmentRow>();
            return;
        }

        var uniqueIpsAll = normalized.Select(s => s.IpAddress).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (MaxUniqueIpsToEnrich > 0 && uniqueIpsAll.Count > MaxUniqueIpsToEnrich)
        {
            ResultsCapped = true;
            uniqueIpsAll = uniqueIpsAll.Take(MaxUniqueIpsToEnrich).ToList();
            var allowed = new HashSet<string>(uniqueIpsAll, StringComparer.OrdinalIgnoreCase);
            normalized = normalized.Where(s => allowed.Contains(s.IpAddress)).ToList();
        }

        UniqueIpCount = uniqueIpsAll.Count;

        var rdapFailures = 0;
        var rdnsFailures = 0;
        var ptrMissing = 0;

        var enriched = new ConcurrentDictionary<string, IpEnrichmentDetails>(StringComparer.OrdinalIgnoreCase);
        var cap = Math.Max(1, MaxParallelism);
        using var gate = new SemaphoreSlim(cap);

        var tasks = uniqueIpsAll.Select(async ip =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var details = await EnrichIpAsync(ip, logger, cancellationToken).ConfigureAwait(false);
                enriched[ip] = details;
                if (!details.RdapSucceeded && details.RdapAttempted) Interlocked.Increment(ref rdapFailures);
                if (!details.ReverseDnsSucceeded && details.ReverseDnsAttempted) Interlocked.Increment(ref rdnsFailures);
                if (details.ReverseDnsSucceeded && details.PtrRecords.Count == 0) Interlocked.Increment(ref ptrMissing);
            }
            finally
            {
                gate.Release();
            }
        }).ToList();

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
            QuerySucceeded = true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            QuerySucceeded = false;
            FailureReason = ex.Message;
            logger?.WriteErrorCode(IpEnrichmentCodes.DnsQueryFailed, "IP enrichment failed: {0}", ex.Message);
            return;
        }

        var rows = new List<IpEnrichmentRow>(normalized.Count);
        foreach (var src in normalized)
        {
            if (!enriched.TryGetValue(src.IpAddress, out var d))
            {
                d = new IpEnrichmentDetails { IpAddress = src.IpAddress };
            }

            rows.Add(new IpEnrichmentRow
            {
                IpAddress = src.IpAddress,
                AddressFamily = d.AddressFamily,
                SourceKind = src.SourceKind,
                SourceHost = src.SourceHost,
                Ptr = d.PtrRecords.FirstOrDefault() ?? string.Empty,
                PtrRecords = d.PtrRecords.Count > 0 ? string.Join(", ", d.PtrRecords) : string.Empty,
                Asn = d.Asn,
                AsName = d.AsName ?? string.Empty,
                Cidr = d.Cidr ?? string.Empty,
                Country = d.Country ?? string.Empty,
                Region = d.Region ?? string.Empty
            });
        }

        Rows = rows
            .OrderBy(r => r.SourceKind)
            .ThenBy(r => r.SourceHost, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToList();

        RowCount = Rows.Count;

        // Summaries (unique IPs only)
        var uniqDetails = uniqueIpsAll.Select(ip => enriched.TryGetValue(ip, out var d) ? d : new IpEnrichmentDetails { IpAddress = ip }).ToList();
        AsnCounts = uniqDetails
            .Where(d => d.Asn.HasValue)
            .GroupBy(d => d.Asn!.Value)
            .ToDictionary(g => g.Key, g => g.Count());

        CountryCounts = uniqDetails
            .Where(d => !string.IsNullOrWhiteSpace(d.Country))
            .GroupBy(d => d.Country!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        DistinctAsnCount = AsnCounts.Count;
        DistinctCountryCount = CountryCounts.Count;

        logger?.WriteInformationCode(IpEnrichmentCodes.ResultsPresent, "Enriched {0} unique IP(s) ({1} row(s)).", UniqueIpCount, RowCount);
        if (ResultsCapped)
        {
            logger?.WriteInformationCode(IpEnrichmentCodes.ResultsCapped, "IP enrichment results capped at {0} unique IP(s).", MaxUniqueIpsToEnrich);
        }
        if (rdapFailures > 0)
        {
            logger?.WriteWarningCode(IpEnrichmentCodes.RdapLookupFailed, "{0} RDAP lookup(s) failed.", rdapFailures);
        }
        if (rdnsFailures > 0)
        {
            logger?.WriteWarningCode(IpEnrichmentCodes.ReverseDnsFailed, "{0} reverse DNS lookup(s) failed.", rdnsFailures);
        }
        if (ptrMissing > 0)
        {
            logger?.WriteWarningCode(IpEnrichmentCodes.PtrMissing, "{0} IP(s) have no PTR record.", ptrMissing);
        }

        const int highAsnThreshold = 10;
        if (DistinctAsnCount >= highAsnThreshold)
        {
            logger?.WriteWarningCode(IpEnrichmentCodes.HighAsnDiversity, "High ASN diversity observed ({0} ASNs).", DistinctAsnCount);
        }
    }

    private void Reset()
    {
        Subject = null;
        ResultsCapped = false;
        QuerySucceeded = false;
        FailureReason = null;
        UniqueIpCount = 0;
        RowCount = 0;
        DistinctAsnCount = 0;
        DistinctCountryCount = 0;
        AsnCounts = new Dictionary<int, int>();
        CountryCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        Rows = Array.Empty<IpEnrichmentRow>();
        Assessments.Clear();
    }

    private async Task<DnsAnswer[]> QueryDnsAsync(string name, DnsRecordType type, CancellationToken ct)
    {
        if (QueryOverride != null)
        {
            return await QueryOverride(name, type, ct).ConfigureAwait(false);
        }

        return await DnsConfiguration.QueryDNS(name, type, cancellationToken: ct).ConfigureAwait(false);
    }

    private async Task AddApexSourcesAsync(string domain, List<IpEnrichmentSource> sources, CancellationToken ct)
    {
        var a = await QueryDnsAsync(domain, DnsRecordType.A, ct).ConfigureAwait(false);
        var aaaa = await QueryDnsAsync(domain, DnsRecordType.AAAA, ct).ConfigureAwait(false);

        foreach (var ans in a.Concat(aaaa))
        {
            var ip = (ans.Data ?? ans.DataRaw ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(ip)) continue;
            sources.Add(new IpEnrichmentSource
            {
                IpAddress = ip,
                SourceHost = domain,
                SourceKind = IpEnrichmentSourceKind.Apex
            });
        }
    }

    private async Task AddHostSourcesAsync(string domain, DnsRecordType type, IpEnrichmentSourceKind kind, List<IpEnrichmentSource> sources, CancellationToken ct)
    {
        var answers = await QueryDnsAsync(domain, type, ct).ConfigureAwait(false);
        var hosts = new List<string>();
        foreach (var a in answers)
        {
            var raw = (a.Data ?? a.DataRaw ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var host = type == DnsRecordType.MX ? ParseMxTarget(raw) : raw.TrimEnd('.');
            if (string.IsNullOrWhiteSpace(host)) continue;
            if (host == ".") continue;
            if (!hosts.Contains(host, StringComparer.OrdinalIgnoreCase))
            {
                hosts.Add(host);
            }
            if (MaxHostsPerKind > 0 && hosts.Count >= MaxHostsPerKind)
            {
                break;
            }
        }

        foreach (var host in hosts)
        {
            var a = await QueryDnsAsync(host, DnsRecordType.A, ct).ConfigureAwait(false);
            var aaaa = await QueryDnsAsync(host, DnsRecordType.AAAA, ct).ConfigureAwait(false);
            foreach (var ans in a.Concat(aaaa))
            {
                var ip = (ans.Data ?? ans.DataRaw ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(ip)) continue;
                sources.Add(new IpEnrichmentSource
                {
                    IpAddress = ip,
                    SourceHost = host,
                    SourceKind = kind
                });
            }
        }
    }

    private static string ParseMxTarget(string data)
    {
        var parts = data.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 2)
        {
            return parts[1].Trim().TrimEnd('.');
        }
        return data.Trim().TrimEnd('.');
    }

    private static List<IpEnrichmentSource> NormalizeAndDedupeSources(List<IpEnrichmentSource> sources)
    {
        var list = new List<IpEnrichmentSource>(sources.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var s in sources)
        {
            if (s == null) continue;
            var ipRaw = (s.IpAddress ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(ipRaw)) continue;
            if (!TryNormalizeIp(ipRaw, out _, out var canonical)) continue;

            var host = (s.SourceHost ?? string.Empty).Trim().TrimEnd('.');
            var kind = s.SourceKind;
            var key = canonical + "|" + kind + "|" + host;
            if (!seen.Add(key)) continue;

            list.Add(new IpEnrichmentSource
            {
                IpAddress = canonical,
                SourceHost = host,
                SourceKind = kind
            });
        }

        return list;
    }

    private static bool TryNormalizeIp(string value, out IPAddress ipAddress, out string canonical)
    {
        canonical = string.Empty;
        if (!IPAddress.TryParse(value, out var parsed) || parsed == null)
        {
            ipAddress = IPAddress.None;
            return false;
        }

        ipAddress = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;

        canonical = ipAddress.AddressFamily == AddressFamily.InterNetworkV6
            ? IPAddress.Parse(ipAddress.ToString()).ToString()
            : ipAddress.ToString();

        return true;
    }

    private sealed class IpEnrichmentDetails
    {
        public string IpAddress { get; init; } = string.Empty;
        public IpAddressFamilyKind AddressFamily { get; init; } = IpAddressFamilyKind.Unknown;
        public List<string> PtrRecords { get; init; } = new();
        public int? Asn { get; init; }
        public string? AsName { get; init; }
        public string? Cidr { get; init; }
        public string? Country { get; init; }
        public string? Region { get; init; }
        public bool ReverseDnsAttempted { get; init; }
        public bool ReverseDnsSucceeded { get; init; }
        public bool RdapAttempted { get; init; }
        public bool RdapSucceeded { get; init; }
    }

    private async Task<IpEnrichmentDetails> EnrichIpAsync(string ip, InternalLogger? logger, CancellationToken ct)
    {
        if (!TryNormalizeIp(ip, out var parsed, out var canonical))
        {
            return new IpEnrichmentDetails { IpAddress = ip };
        }

        var family = parsed.AddressFamily == AddressFamily.InterNetworkV6 ? IpAddressFamilyKind.IPv6 : IpAddressFamilyKind.IPv4;

        var ptrRecords = new List<string>();
        bool rdnsAttempted = true;
        bool rdnsOk = false;
        try
        {
            var ptrName = parsed.ToPtrFormat() + (family == IpAddressFamilyKind.IPv6 ? ".ip6.arpa" : ".in-addr.arpa");
            var ptrAnswers = await QueryDnsAsync(ptrName, DnsRecordType.PTR, ct).ConfigureAwait(false);
            foreach (var a in ptrAnswers)
            {
                var raw = (a.Data ?? a.DataRaw ?? string.Empty).Trim().TrimEnd('.');
                if (string.IsNullOrWhiteSpace(raw)) continue;
                if (!ptrRecords.Contains(raw, StringComparer.OrdinalIgnoreCase))
                {
                    ptrRecords.Add(raw);
                }
            }
            rdnsOk = true;
        }
        catch (Exception ex)
        {
            logger?.WriteVerbose("PTR lookup failed for {0}: {1}", canonical, ex.Message);
        }

        GeoLocationInfo? geo = null;
        try
        {
            geo = _geo.Lookup(canonical);
        }
        catch
        {
        }

        int? asn = null;
        string? asName = null;
        string? cidr = null;
        string? rdapCountry = null;
        string? rdapName = null;
        bool rdapAttempted = true;
        bool rdapOk = false;
        try
        {
            var rdap = await QueryRdapIpAsync(canonical, ct).ConfigureAwait(false);
            if (rdap != null)
            {
                cidr = rdap.Cidr;
                rdapCountry = rdap.Country;
                rdapName = rdap.Name;
                (asn, asName) = TryExtractAsn(rdap);
                if (string.IsNullOrWhiteSpace(asName))
                {
                    asName = rdapName;
                }
            }
            rdapOk = true;
        }
        catch (Exception ex)
        {
            logger?.WriteVerbose("RDAP lookup failed for {0}: {1}", canonical, ex.Message);
        }

        var country = geo?.Country;
        var region = geo?.Region;
        if (string.IsNullOrWhiteSpace(country)) country = rdapCountry;

        return new IpEnrichmentDetails
        {
            IpAddress = canonical,
            AddressFamily = family,
            PtrRecords = ptrRecords,
            Asn = asn,
            AsName = asName,
            Cidr = cidr,
            Country = country,
            Region = region,
            ReverseDnsAttempted = rdnsAttempted,
            ReverseDnsSucceeded = rdnsOk,
            RdapAttempted = rdapAttempted,
            RdapSucceeded = rdapOk
        };
    }

    private async Task<RdapIpNetwork?> QueryRdapIpAsync(string ipOrCidr, CancellationToken ct)
    {
        if (RdapQueryOverride != null)
        {
            return await RdapQueryOverride(ipOrCidr, ct).ConfigureAwait(false);
        }

        return await RdapClient.GetIp(ipOrCidr, ct).ConfigureAwait(false);
    }

    private static (int? Asn, string? AsName) TryExtractAsn(RdapIpNetwork rdap)
    {
        if (rdap == null || rdap.Entities == null || rdap.Entities.Length == 0)
        {
            return (null, null);
        }

        foreach (var ent in rdap.Entities)
        {
            var handle = ent?.Handle ?? string.Empty;
            if (!handle.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            int? asn = null;
            if (int.TryParse(handle.TrimStart('A', 'S', 'a', 's'), out var a))
            {
                asn = a;
            }

            string? asName = null;
            try
            {
                if (ent?.VcardArray.HasValue == true && ent.VcardArray.Value.ValueKind == JsonValueKind.Array && ent.VcardArray.Value.GetArrayLength() > 1)
                {
                    foreach (var card in ent.VcardArray.Value[1].EnumerateArray())
                    {
                        if (card.GetArrayLength() > 3 && string.Equals(card[0].GetString(), "fn", StringComparison.OrdinalIgnoreCase))
                        {
                            asName = card[3].GetString();
                            break;
                        }
                    }
                }
            }
            catch
            {
            }

            return (asn, asName);
        }

        return (null, null);
    }
}
