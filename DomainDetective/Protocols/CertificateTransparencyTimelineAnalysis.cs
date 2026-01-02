using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Builds a certificate transparency (CT) timeline for a domain and summarizes
/// issuer diversity, certificate validity status, and basic anomalies.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class CertificateTransparencyTimelineAnalysis : IHasAssessments
{
    /// <summary>The domain being analyzed.</summary>
    public string? Subject { get; private set; }

    /// <summary>CT query template for wildcard query (includes subdomains).</summary>
    public string CrtShWildcardUrlTemplate { get; set; } = "https://crt.sh/?q=%25.{0}&output=json";

    /// <summary>CT query template for exact-name query (covers apex-only certificates).</summary>
    public string CrtShExactUrlTemplate { get; set; } = "https://crt.sh/?q={0}&output=json";

    /// <summary>
    /// Optional override returning the JSON payload for a given CT URL.
    /// Used by tests and offline callers.
    /// </summary>
    public Func<string, CancellationToken, Task<string>>? QueryOverride { get; set; }

    /// <summary>True when CT query succeeded and parsing completed.</summary>
    public bool QuerySucceeded { get; private set; }

    /// <summary>If <see cref="QuerySucceeded"/> is false, this may contain a short reason.</summary>
    public string? FailureReason { get; private set; }

    /// <summary>Total number of CT rows processed (may include duplicates).</summary>
    public int CertificateObservationCount { get; private set; }

    /// <summary>Total number of unique certificates observed (deduped).</summary>
    public int UniqueCertificateCount { get; private set; }

    /// <summary>Earliest CT entry timestamp observed.</summary>
    public DateTimeOffset? FirstSeenUtc { get; private set; }

    /// <summary>Latest CT entry timestamp observed.</summary>
    public DateTimeOffset? LastSeenUtc { get; private set; }

    /// <summary>Distinct issuer count observed across unique certificates.</summary>
    public int DistinctIssuerCount => IssuerCounts.Count;

    /// <summary>Issuer name → count (unique certificates, best-effort).</summary>
    public IReadOnlyDictionary<string, int> IssuerCounts { get; private set; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Number of currently active certificates (based on validity window).</summary>
    public int ActiveCertificateCount { get; private set; }

    /// <summary>Number of expired certificates (based on validity window).</summary>
    public int ExpiredCertificateCount { get; private set; }

    /// <summary>Number of certificates not yet valid (based on validity window).</summary>
    public int NotYetValidCertificateCount { get; private set; }

    /// <summary>Number of wildcard certificates observed (common name or SAN contains '*').</summary>
    public int WildcardCertificateCount { get; private set; }

    /// <summary>Unique certificates issued in the last 7 days (based on CT entry timestamp).</summary>
    public int IssuedLast7Days { get; private set; }

    /// <summary>Unique certificates issued in the last 30 days (based on CT entry timestamp).</summary>
    public int IssuedLast30Days { get; private set; }

    /// <summary>True when processing was capped to protect performance.</summary>
    public bool ResultsCapped { get; private set; }

    /// <summary>Maximum number of CT rows to process across all queries.</summary>
    public int MaxCtRowsToProcess { get; set; } = 10_000;

    /// <summary>Maximum number of unique certificates to retain in memory.</summary>
    public int MaxUniqueCertificates { get; set; } = 10_000;

    /// <summary>Maximum number of timeline buckets to keep.</summary>
    public int MaxTimelineBuckets { get; set; } = 240;

    /// <summary>Maximum number of recent certificate samples to keep.</summary>
    public int MaxRecentCertificates { get; set; } = 200;

    /// <summary>CT timeline buckets (monthly) based on entry timestamps.</summary>
    public IReadOnlyList<CtTimelineBucket> Timeline { get; private set; } = Array.Empty<CtTimelineBucket>();

    /// <summary>Most recent unique certificates (sample) sorted by entry timestamp descending.</summary>
    public IReadOnlyList<CtCertificateSample> RecentCertificates { get; private set; } = Array.Empty<CtCertificateSample>();

    /// <summary>Assessment collection for report-friendly output.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>
    /// Performs CT-backed timeline analysis for the specified <paramref name="domain"/>.
    /// </summary>
    public async Task AnalyzeAsync(string domain, InternalLogger? logger = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        Reset();
        Subject = DomainHelper.ValidateIdn(domain);

        var urls = BuildQueryUrls(Subject!);
        if (urls.Count == 0)
        {
            QuerySucceeded = true;
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var issuerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var certs = new Dictionary<string, CtCertificateAggregate>(StringComparer.OrdinalIgnoreCase);
        var bucketAgg = new Dictionary<int, CtBucketAggregate>();

        try
        {
            foreach (var url in urls)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var json = await FetchJsonAsync(url, cancellationToken).ConfigureAwait(false);
                ParseCtJson(json, now, issuerCounts, certs, bucketAgg, logger);
                if (ResultsCapped)
                {
                    break;
                }
            }

            QuerySucceeded = true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (JsonException ex)
        {
            QuerySucceeded = false;
            FailureReason = ex.Message;
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Error,
                Category = "CT Timeline",
                Code = CtTimelineCodes.ParseFailed,
                Target = Subject,
                Message = $"CT response parsing failed: {ex.Message}"
            });
            return;
        }
        catch (Exception ex)
        {
            QuerySucceeded = false;
            FailureReason = ex.Message;
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Error,
                Category = "CT Timeline",
                Code = CtTimelineCodes.QueryFailed,
                Target = Subject,
                Message = $"CT query failed: {ex.Message}"
            });
            return;
        }

        IssuerCounts = issuerCounts;
        UniqueCertificateCount = certs.Count;
        Timeline = BuildTimeline(bucketAgg);
        RecentCertificates = BuildRecent(certs.Values, MaxRecentCertificates);

        if (!QuerySucceeded)
        {
            return;
        }

        if (UniqueCertificateCount == 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "CT Timeline",
                Code = CtTimelineCodes.NoResults,
                Target = Subject,
                Message = "No certificate transparency results found."
            });
            return;
        }

        Assessments.Add(new Assessment
        {
            Severity = AssessmentSeverity.Info,
            Category = "CT Timeline",
            Code = CtTimelineCodes.ResultsPresent,
            Target = Subject,
            Message = $"Observed {UniqueCertificateCount} unique certificate(s) across {DistinctIssuerCount} issuer(s)."
        });

        if (ResultsCapped)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "CT Timeline",
                Code = CtTimelineCodes.ResultsCapped,
                Target = Subject,
                Message = $"CT processing capped at {Math.Max(0, MaxCtRowsToProcess)} row(s) / {Math.Max(0, MaxUniqueCertificates)} certificate(s)."
            });
        }

        if (ActiveCertificateCount == 0 && (ExpiredCertificateCount + NotYetValidCertificateCount) > 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "CT Timeline",
                Code = CtTimelineCodes.NoActiveCertificates,
                Target = Subject,
                Message = "No currently active certificates were observed in CT results."
            });
        }

        const int highIssuerThreshold = 10;
        if (DistinctIssuerCount >= highIssuerThreshold)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "CT Timeline",
                Code = CtTimelineCodes.HighIssuerDiversity,
                Target = Subject,
                Message = $"High issuer diversity observed ({DistinctIssuerCount} issuers)."
            });
        }

        const int issuanceVelocityThreshold7d = 25;
        if (IssuedLast7Days >= issuanceVelocityThreshold7d)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "CT Timeline",
                Code = CtTimelineCodes.HighIssuanceVelocity,
                Target = Subject,
                Message = $"High certificate issuance volume in last 7 days: {IssuedLast7Days}."
            });
        }
    }

    private void Reset()
    {
        Subject = null;
        QuerySucceeded = false;
        FailureReason = null;
        CertificateObservationCount = 0;
        UniqueCertificateCount = 0;
        FirstSeenUtc = null;
        LastSeenUtc = null;
        IssuerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        ActiveCertificateCount = 0;
        ExpiredCertificateCount = 0;
        NotYetValidCertificateCount = 0;
        WildcardCertificateCount = 0;
        IssuedLast7Days = 0;
        IssuedLast30Days = 0;
        ResultsCapped = false;
        Timeline = Array.Empty<CtTimelineBucket>();
        RecentCertificates = Array.Empty<CtCertificateSample>();
        Assessments.Clear();
    }

    private List<string> BuildQueryUrls(string domain)
    {
        var list = new List<string>(2);
        if (!string.IsNullOrWhiteSpace(CrtShWildcardUrlTemplate))
        {
            list.Add(string.Format(CrtShWildcardUrlTemplate, domain));
        }
        if (!string.IsNullOrWhiteSpace(CrtShExactUrlTemplate))
        {
            list.Add(string.Format(CrtShExactUrlTemplate, domain));
        }
        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<string> FetchJsonAsync(string url, CancellationToken cancellationToken)
    {
        if (QueryOverride != null)
        {
            return await QueryOverride(url, cancellationToken).ConfigureAwait(false);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await SharedHttpClient.Instance.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    private readonly struct CtRow
    {
        public CtRow(
            string? issuerName,
            string? commonName,
            string? nameValue,
            string? serialNumber,
            int? id,
            DateTimeOffset? entryTimestampUtc,
            DateTimeOffset? notBeforeUtc,
            DateTimeOffset? notAfterUtc)
        {
            IssuerName = issuerName;
            CommonName = commonName;
            NameValue = nameValue;
            SerialNumber = serialNumber;
            Id = id;
            EntryTimestampUtc = entryTimestampUtc;
            NotBeforeUtc = notBeforeUtc;
            NotAfterUtc = notAfterUtc;
        }

        public string? IssuerName { get; }
        public string? CommonName { get; }
        public string? NameValue { get; }
        public string? SerialNumber { get; }
        public int? Id { get; }
        public DateTimeOffset? EntryTimestampUtc { get; }
        public DateTimeOffset? NotBeforeUtc { get; }
        public DateTimeOffset? NotAfterUtc { get; }
    }

    private void ParseCtJson(
        string json,
        DateTimeOffset nowUtc,
        Dictionary<string, int> issuerCounts,
        Dictionary<string, CtCertificateAggregate> certs,
        Dictionary<int, CtBucketAggregate> bucketAgg,
        InternalLogger? logger)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return;
        }

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var item in doc.RootElement.EnumerateArray())
        {
            if (!TryStartNextCtObservation())
            {
                break;
            }

            var row = ReadCtRow(item);
            UpdateFirstAndLastSeen(row.EntryTimestampUtc);

            var key = BuildCertificateKey(row.Id, row.IssuerName, row.SerialNumber, row.NotBeforeUtc, row.NotAfterUtc, row.CommonName, row.NameValue);
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            if (certs.ContainsKey(key))
            {
                continue;
            }

            if (!TryAddUniqueCertificate(key, row, nowUtc, issuerCounts, certs, bucketAgg))
            {
                break;
            }
        }

        logger?.WriteVerbose("CT timeline processed {0} row(s), {1} unique certificate(s) for {2}", CertificateObservationCount, certs.Count, Subject);
    }

    private bool TryStartNextCtObservation()
    {
        if (MaxCtRowsToProcess > 0 && CertificateObservationCount >= MaxCtRowsToProcess)
        {
            ResultsCapped = true;
            return false;
        }

        CertificateObservationCount++;
        return true;
    }

    private static CtRow ReadCtRow(JsonElement item)
    {
        var issuerName = GetString(item, "issuer_name");
        var commonName = GetString(item, "common_name");
        var nameValue = GetString(item, "name_value");
        var serial = GetString(item, "serial_number");
        var id = GetInt(item, "id") ?? GetInt(item, "min_cert_id");

        var entryTs = ParseTimestamp(GetString(item, "entry_timestamp"));
        var notBefore = ParseTimestamp(GetString(item, "not_before"));
        var notAfter = ParseTimestamp(GetString(item, "not_after"));

        return new CtRow(
            issuerName: issuerName,
            commonName: commonName,
            nameValue: nameValue,
            serialNumber: serial,
            id: id,
            entryTimestampUtc: entryTs,
            notBeforeUtc: notBefore,
            notAfterUtc: notAfter);
    }

    private void UpdateFirstAndLastSeen(DateTimeOffset? entryTimestampUtc)
    {
        if (!entryTimestampUtc.HasValue)
        {
            return;
        }

        var entry = entryTimestampUtc.Value;
        if (!FirstSeenUtc.HasValue || entry < FirstSeenUtc.Value)
        {
            FirstSeenUtc = entry;
        }
        if (!LastSeenUtc.HasValue || entry > LastSeenUtc.Value)
        {
            LastSeenUtc = entry;
        }
    }

    private bool TryAddUniqueCertificate(
        string key,
        CtRow row,
        DateTimeOffset nowUtc,
        Dictionary<string, int> issuerCounts,
        Dictionary<string, CtCertificateAggregate> certs,
        Dictionary<int, CtBucketAggregate> bucketAgg)
    {
        if (MaxUniqueCertificates > 0 && certs.Count >= MaxUniqueCertificates)
        {
            ResultsCapped = true;
            return false;
        }

        var isWildcard = DetectWildcard(row.CommonName, row.NameValue);
        var status = GetValidityStatus(nowUtc, row.NotBeforeUtc, row.NotAfterUtc);

        certs[key] = new CtCertificateAggregate
        {
            Key = key,
            IssuerName = row.IssuerName ?? string.Empty,
            CommonName = row.CommonName ?? string.Empty,
            EntryTimestampUtc = row.EntryTimestampUtc,
            NotBeforeUtc = row.NotBeforeUtc,
            NotAfterUtc = row.NotAfterUtc,
            ValidityStatus = status,
            Wildcard = isWildcard
        };

        UpdateIssuerCounts(issuerCounts, row.IssuerName);

        if (isWildcard)
        {
            WildcardCertificateCount++;
        }

        IncrementValidityCounters(status);

        if (row.EntryTimestampUtc.HasValue)
        {
            return UpdateIssuedCountersAndTimeline(nowUtc, row.EntryTimestampUtc.Value, row.IssuerName, bucketAgg);
        }

        return true;
    }

    private static void UpdateIssuerCounts(Dictionary<string, int> issuerCounts, string? issuerName)
    {
        if (issuerName == null)
        {
            return;
        }

        var key = issuerName.Trim();
        if (key.Length == 0)
        {
            return;
        }

        issuerCounts[key] = issuerCounts.TryGetValue(key, out var c) ? c + 1 : 1;
    }

    private void IncrementValidityCounters(CtCertificateValidityStatus status)
    {
        switch (status)
        {
            case CtCertificateValidityStatus.Active:
                ActiveCertificateCount++;
                break;
            case CtCertificateValidityStatus.Expired:
                ExpiredCertificateCount++;
                break;
            case CtCertificateValidityStatus.NotYetValid:
                NotYetValidCertificateCount++;
                break;
        }
    }

    private bool UpdateIssuedCountersAndTimeline(
        DateTimeOffset nowUtc,
        DateTimeOffset entryTimestampUtc,
        string? issuerName,
        Dictionary<int, CtBucketAggregate> bucketAgg)
    {
        var age = nowUtc - entryTimestampUtc;
        if (age <= TimeSpan.FromDays(7))
        {
            IssuedLast7Days++;
        }
        if (age <= TimeSpan.FromDays(30))
        {
            IssuedLast30Days++;
        }

        var ym = YearMonthKey(entryTimestampUtc);
        if (ym <= 0)
        {
            return true;
        }

        if (!bucketAgg.TryGetValue(ym, out var b))
        {
            if (MaxTimelineBuckets > 0 && bucketAgg.Count >= MaxTimelineBuckets)
            {
                ResultsCapped = true;
                return false;
            }

            b = new CtBucketAggregate(ym);
            bucketAgg[ym] = b;
        }

        b.UniqueCertificates++;
        if (issuerName != null)
        {
            var issuerKey = issuerName.Trim();
            if (issuerKey.Length > 0)
            {
                b.Issuers.Add(issuerKey);
            }
        }

        return true;
    }

    private static string? GetString(JsonElement obj, string prop)
    {
        if (obj.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!obj.TryGetProperty(prop, out var p))
        {
            return null;
        }

        return p.ValueKind == JsonValueKind.String ? p.GetString() : p.ToString();
    }

    private static int? GetInt(JsonElement obj, string prop)
    {
        if (obj.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!obj.TryGetProperty(prop, out var p))
        {
            return null;
        }

        if (p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out var i))
        {
            return i;
        }

        if (p.ValueKind == JsonValueKind.String && int.TryParse(p.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var si))
        {
            return si;
        }

        return null;
    }

    private static DateTimeOffset? ParseTimestamp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
        {
            return dt;
        }

        return DateTimeOffset.TryParse(value, out dt) ? dt : null;
    }

    private static int YearMonthKey(DateTimeOffset dt)
    {
        try
        {
            return (dt.Year * 100) + dt.Month;
        }
        catch
        {
            return 0;
        }
    }

    private static string BuildCertificateKey(
        int? id,
        string? issuerName,
        string? serial,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter,
        string? commonName,
        string? nameValue)
    {
        if (id.HasValue && id.Value > 0)
        {
            return "id:" + id.Value.ToString(CultureInfo.InvariantCulture);
        }

        var issuer = (issuerName ?? string.Empty).Trim();
        var ser = (serial ?? string.Empty).Trim();
        var nb = notBefore?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
        var na = notAfter?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
        var cn = (commonName ?? string.Empty).Trim();
        var nv = (nameValue ?? string.Empty).Trim();

        // Fallback key: issuer + serial + validity window + CN + SAN blob (capped)
        if (nv.Length > 512) nv = nv.Substring(0, 512);
        if (cn.Length > 256) cn = cn.Substring(0, 256);
        return $"{issuer}|{ser}|{nb}|{na}|{cn}|{nv}";
    }

    private static bool DetectWildcard(string? commonName, string? nameValue)
    {
        if (!string.IsNullOrWhiteSpace(commonName) && commonName!.TrimStart().StartsWith("*.", StringComparison.Ordinal))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(nameValue))
        {
            foreach (var n in nameValue!.Split('\n'))
            {
                var s = n.TrimStart();
                if (s.StartsWith("*.", StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static CtCertificateValidityStatus GetValidityStatus(DateTimeOffset nowUtc, DateTimeOffset? notBefore, DateTimeOffset? notAfter)
    {
        if (notBefore.HasValue && nowUtc < notBefore.Value)
        {
            return CtCertificateValidityStatus.NotYetValid;
        }

        if (notAfter.HasValue && nowUtc > notAfter.Value)
        {
            return CtCertificateValidityStatus.Expired;
        }

        if (notBefore.HasValue && notAfter.HasValue && nowUtc >= notBefore.Value && nowUtc <= notAfter.Value)
        {
            return CtCertificateValidityStatus.Active;
        }

        // Best-effort: if we have only one bound, infer.
        if (!notBefore.HasValue && notAfter.HasValue)
        {
            return nowUtc <= notAfter.Value ? CtCertificateValidityStatus.Active : CtCertificateValidityStatus.Expired;
        }
        if (notBefore.HasValue && !notAfter.HasValue)
        {
            return nowUtc >= notBefore.Value ? CtCertificateValidityStatus.Active : CtCertificateValidityStatus.NotYetValid;
        }

        return CtCertificateValidityStatus.Unknown;
    }

    private static IReadOnlyList<CtTimelineBucket> BuildTimeline(Dictionary<int, CtBucketAggregate> agg)
    {
        if (agg.Count == 0)
        {
            return Array.Empty<CtTimelineBucket>();
        }

        return agg.Values
            .OrderBy(x => x.YearMonthKey)
            .Select(x => new CtTimelineBucket
            {
                Year = x.Year,
                Month = x.Month,
                UniqueCertificates = x.UniqueCertificates,
                DistinctIssuers = x.Issuers.Count
            })
            .ToList();
    }

    private static IReadOnlyList<CtCertificateSample> BuildRecent(IEnumerable<CtCertificateAggregate> certs, int take)
    {
        if (take <= 0)
        {
            return Array.Empty<CtCertificateSample>();
        }

        return certs
            .Where(c => c.EntryTimestampUtc.HasValue)
            .OrderByDescending(c => c.EntryTimestampUtc)
            .Take(take)
            .Select(c => new CtCertificateSample
            {
                EntryTimestampUtc = c.EntryTimestampUtc,
                NotAfterUtc = c.NotAfterUtc,
                IssuerName = c.IssuerName,
                CommonName = c.CommonName,
                ValidityStatus = c.ValidityStatus,
                Wildcard = c.Wildcard
            })
            .ToList();
    }

    private sealed class CtCertificateAggregate
    {
        public string Key { get; init; } = string.Empty;
        public string IssuerName { get; init; } = string.Empty;
        public string CommonName { get; init; } = string.Empty;
        public DateTimeOffset? EntryTimestampUtc { get; init; }
        public DateTimeOffset? NotBeforeUtc { get; init; }
        public DateTimeOffset? NotAfterUtc { get; init; }
        public CtCertificateValidityStatus ValidityStatus { get; init; }
        public bool Wildcard { get; init; }
    }

    private sealed class CtBucketAggregate
    {
        public CtBucketAggregate(int yearMonthKey)
        {
            YearMonthKey = yearMonthKey;
            Year = yearMonthKey / 100;
            Month = yearMonthKey % 100;
        }

        public int YearMonthKey { get; }
        public int Year { get; }
        public int Month { get; }
        public int UniqueCertificates { get; set; }
        public HashSet<string> Issuers { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>Validity status for a CT-observed certificate.</summary>
public enum CtCertificateValidityStatus
{
    Unknown = 0,
    Active = 1,
    Expired = 2,
    NotYetValid = 3
}

/// <summary>Monthly bucket for CT entries.</summary>
public sealed class CtTimelineBucket
{
    public int Year { get; init; }
    public int Month { get; init; }
    public int UniqueCertificates { get; init; }
    public int DistinctIssuers { get; init; }

    public override string ToString()
    {
        if (Year <= 0 || Month <= 0) return "-";
        return Year.ToString("0000", CultureInfo.InvariantCulture) + "-" + Month.ToString("00", CultureInfo.InvariantCulture);
    }
}

/// <summary>Sample row for recent CT certificates.</summary>
public sealed class CtCertificateSample
{
    public DateTimeOffset? EntryTimestampUtc { get; init; }
    public DateTimeOffset? NotAfterUtc { get; init; }
    public string IssuerName { get; init; } = string.Empty;
    public string CommonName { get; init; } = string.Empty;
    public CtCertificateValidityStatus ValidityStatus { get; init; }
    public bool Wildcard { get; init; }
}
