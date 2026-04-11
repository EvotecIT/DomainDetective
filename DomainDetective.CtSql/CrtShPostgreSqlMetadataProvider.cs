using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DBAClientX;
using DomainDetective;

namespace DomainDetective.CtSql;

internal sealed class CrtShPostgreSqlMetadataProvider : ICtSqlMetadataProvider {
    private readonly PostgreSql _client = new();

    public async Task<SubdomainDiscoveryEntry?> QueryExactMetadataAsync(
        string hostName,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        ISet<string>? targetedThumbprints,
        CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(hostName) || options == null) {
            return null;
        }

        string normalizedHost = hostName.Trim().TrimEnd('.').ToLowerInvariant();
        IReadOnlyList<CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow> rows = await _client.QueryAsListAsync(
            BuildCrtShPostgreSqlConnectionString(options),
            CertificateInventoryCapture.BuildCrtShPostgreSqlExactMetadataQuery(),
            MapRow,
            new Dictionary<string, object?> {
                ["host"] = normalizedHost
            },
            cancellationToken: cancellationToken).ConfigureAwait(false);

        SubdomainDiscoveryEntry? entry = CertificateInventoryCapture.TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows(
            normalizedHost,
            rows,
            targetedThumbprints);
        if (entry != null) {
            logger?.WriteVerbose(
                "CT metadata backfill exact PostgreSQL lookup matched {0} row(s) for {1}.",
                rows.Count,
                normalizedHost);
        }

        return entry;
    }

    public async Task<IReadOnlyDictionary<string, SubdomainDiscoveryEntry>> QueryDomainMetadataAsync(
        string domain,
        IReadOnlyCollection<string> hostNames,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        ISet<string>? targetedThumbprints,
        CancellationToken cancellationToken) {
        var results = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(domain) || hostNames == null || hostNames.Count == 0 || options == null) {
            return results;
        }

        string normalizedDomain = domain.Trim().TrimEnd('.').ToLowerInvariant();
        List<string> normalizedHosts = hostNames
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(static host => host.Trim().TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (normalizedHosts.Count == 0) {
            return results;
        }

        IReadOnlyList<CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow> rows = await _client.QueryAsListAsync(
            BuildCrtShPostgreSqlConnectionString(options),
            CertificateInventoryCapture.BuildCrtShPostgreSqlDomainMetadataQuery(),
            MapRow,
            new Dictionary<string, object?> {
                ["domain"] = normalizedDomain,
                ["hosts"] = normalizedHosts.ToArray(),
                ["wildcardHosts"] = normalizedHosts.Select(CertificateInventoryCapture.BuildWildcardCandidateHost).ToArray(),
                ["limit"] = Math.Min(Math.Max(32, normalizedHosts.Count * 8), 512)
            },
            cancellationToken: cancellationToken).ConfigureAwait(false);

        foreach (string normalizedHost in normalizedHosts) {
            SubdomainDiscoveryEntry? entry = CertificateInventoryCapture.TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows(
                normalizedHost,
                rows,
                targetedThumbprints);
            if (entry == null || string.IsNullOrWhiteSpace(entry.Name)) {
                continue;
            }

            results[normalizedHost] = entry;
        }

        if (results.Count > 0) {
            logger?.WriteVerbose(
                "CT metadata backfill domain PostgreSQL lookup matched {0} host(s) for {1} from {2} candidate certificate row(s).",
                results.Count,
                normalizedDomain,
                rows.Count);
        }

        return results;
    }

    private static CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow MapRow(IDataRecord row) {
        return new CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow {
            CertificateDer = row.IsDBNull(0) ? null : (byte[])row.GetValue(0),
            EntryTimestampUtc = row.IsDBNull(1) ? null : ReadDateTimeOffset(row.GetValue(1)),
            CommonName = row.IsDBNull(2) ? null : row.GetString(2),
            IssuerName = row.IsDBNull(3) ? null : row.GetString(3),
            SerialNumber = row.IsDBNull(4) ? null : row.GetString(4),
            NotBeforeUtc = row.IsDBNull(5) ? null : ReadDateTimeOffset(row.GetValue(5)),
            NotAfterUtc = row.IsDBNull(6) ? null : ReadDateTimeOffset(row.GetValue(6)),
            CandidateNames = row.IsDBNull(7)
                ? Array.Empty<string>()
                : ((string[])row.GetValue(7))
                    .Select(static name => NormalizeCtMetadataCandidate(name, preserveWildcard: true))
                    .Where(static name => !string.IsNullOrWhiteSpace(name))
                    .Select(static name => name!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList()
        };
    }

    private static string BuildCrtShPostgreSqlConnectionString(CertificateInventoryCaptureOptions options) {
        if (!string.IsNullOrWhiteSpace(options?.CrtShPostgreSqlConnectionString)) {
            return options!.CrtShPostgreSqlConnectionString!;
        }

        int timeoutSeconds = Math.Max(1, options?.CrtShPostgreSqlCommandTimeoutSeconds ?? 15);
        return PostgreSql.BuildConnectionString(
            host: "crt.sh",
            database: "certwatch",
            username: "guest",
            password: string.Empty,
            port: 5432,
            ssl: true) +
            $";Timeout={timeoutSeconds};Command Timeout={timeoutSeconds}";
    }

    private static DateTimeOffset? ReadDateTimeOffset(object? value) {
        return value switch {
            null => null,
            DateTimeOffset dateTimeOffset => dateTimeOffset.ToUniversalTime(),
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => DateTimeOffset.TryParse(
                value.ToString(),
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset parsed)
                ? parsed
                : (DateTimeOffset?)null
        };
    }

    private static string? NormalizeCtMetadataCandidate(string? value, bool preserveWildcard = false) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        string normalized = value!.Trim().TrimEnd('.').ToLowerInvariant();
        while (!preserveWildcard && normalized.StartsWith("*.", StringComparison.Ordinal)) {
            normalized = normalized.Substring(2);
        }

        return normalized.Length == 0 ? null : normalized;
    }
}
