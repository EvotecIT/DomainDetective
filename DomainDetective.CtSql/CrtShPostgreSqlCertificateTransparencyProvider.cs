using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using DBAClientX;
using DomainDetective;
using DomainDetective.Helpers;

namespace DomainDetective.CtSql;

/// <summary>
/// DbaClientX-backed crt.sh PostgreSQL provider for CT certificate queries and legacy inventory metadata backfill.
/// </summary>
public sealed class CrtShPostgreSqlCertificateTransparencyProvider : ICtCertificateTransparencyProvider, IDisposable {
    private const int DefaultExactLookupLimit = 16;
    private const int DefaultHistoryLimit = 100;
    private const int DefaultExpansionLimit = 500;
    private const int DefaultDomainTreeLimit = 100;
    internal const string DefaultCrtShPostgreSqlHostName = "crt.sh";
    // Last verified against crt.sh DNS in April 2026. Update this fallback if crt.sh moves.
    internal const string DefaultCrtShPostgreSqlPinnedIpv4Address = "91.199.212.73";

    private readonly ICrtShPostgreSqlQueryClient _client;
    private readonly CertificateInventoryCaptureOptions _options;

    /// <summary>
    /// Creates a provider using the public crt.sh PostgreSQL connection defaults from <see cref="CertificateInventoryCaptureOptions"/>.
    /// </summary>
    public CrtShPostgreSqlCertificateTransparencyProvider()
        : this(new CertificateInventoryCaptureOptions(), new DbaClientXCrtShPostgreSqlQueryClient()) {
    }

    /// <summary>
    /// Creates a provider using caller-supplied crt.sh PostgreSQL options.
    /// </summary>
    /// <param name="options">Connection string, command timeout, and concurrency options.</param>
    public CrtShPostgreSqlCertificateTransparencyProvider(CertificateInventoryCaptureOptions options)
        : this(options ?? throw new ArgumentNullException(nameof(options)), new DbaClientXCrtShPostgreSqlQueryClient()) {
    }

    internal CrtShPostgreSqlCertificateTransparencyProvider(
        CertificateInventoryCaptureOptions options,
        ICrtShPostgreSqlQueryClient client) {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _client = client ?? throw new ArgumentNullException(nameof(client));
        Profile = CtProviderProfiles.CreateCrtShPostgreSql(_options);
    }

    /// <inheritdoc />
    public string ProviderId => CtProviderProfiles.CrtShPostgreSqlProviderId;

    /// <inheritdoc />
    public CtProviderProfile Profile { get; }

    /// <inheritdoc />
    public async Task<CtCertificateQueryResult> QueryAsync(
        CtCertificateQuery query,
        CtProviderRuntimeState? runtimeState = null,
        CancellationToken cancellationToken = default) {
        CtCertificateQuery normalized = (query ?? throw new ArgumentNullException(nameof(query))).Normalize();
        string normalizedName = NormalizeHostOrDomain(normalized.Name);
        if (string.IsNullOrWhiteSpace(normalizedName)) {
            throw new ArgumentException("CT query name is required.", nameof(query));
        }

        using CancellationTokenSource timeout = CreateTimeoutTokenSource(normalized, cancellationToken);
        CancellationToken effectiveCancellationToken = timeout.Token;
        Stopwatch stopwatch = Stopwatch.StartNew();
        try {
            CtCertificateQueryResult result = normalized.QueryKind switch {
                CtCertificateQueryKind.DomainExpansion => await QueryDomainExpansionAsync(normalized, normalizedName, effectiveCancellationToken).ConfigureAwait(false),
                CtCertificateQueryKind.ExactHostHistory => await QueryExactHostCertificatesAsync(normalized, normalizedName, latestOnly: false, effectiveCancellationToken).ConfigureAwait(false),
                CtCertificateQueryKind.DomainTreeCertificates => await QueryDomainTreeCertificatesAsync(normalized, normalizedName, effectiveCancellationToken).ConfigureAwait(false),
                _ => await QueryExactHostCertificatesAsync(normalized, normalizedName, latestOnly: true, effectiveCancellationToken).ConfigureAwait(false)
            };

            stopwatch.Stop();
            return WithProviderState(result, runtimeState, CtProviderOutcomeKind.Success, stopwatch.Elapsed, null);
        } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) {
            stopwatch.Stop();
            throw new CtProviderQueryException(
                ProviderId,
                CtProviderOutcomeKind.Timeout,
                $"crt.sh PostgreSQL query timed out after {ResolveTimeout(normalized).TotalSeconds:n0} seconds.",
                providerErrorCode: "timeout");
        } catch (DbaQueryExecutionException ex) {
            stopwatch.Stop();
            throw CreateProviderQueryException(ex);
        }
    }

    internal async Task<SubdomainDiscoveryEntry?> QueryExactMetadataAsync(
        string hostName,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        ISet<string>? targetedThumbprints,
        CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(hostName) || options == null) {
            return null;
        }

        string normalizedHost = NormalizeHostOrDomain(hostName);
        IReadOnlyList<CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow> rows;
        try {
            rows = await QueryCertificateRowsAsync(
                BuildCrtShPostgreSqlConnectionString(options),
                CertificateInventoryCapture.BuildCrtShPostgreSqlExactMetadataQuery(),
                new Dictionary<string, object?> {
                    ["host"] = normalizedHost,
                    ["limit"] = DefaultExactLookupLimit
                },
                cancellationToken).ConfigureAwait(false);
        } catch (DbaQueryExecutionException ex) {
            throw new InvalidOperationException("crt.sh PostgreSQL exact metadata query failed.", ex);
        }

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

    internal async Task<IReadOnlyDictionary<string, SubdomainDiscoveryEntry>> QueryDomainMetadataAsync(
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

        string normalizedDomain = NormalizeHostOrDomain(domain);
        List<string> normalizedHosts = hostNames
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(NormalizeHostOrDomain)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (normalizedHosts.Count == 0) {
            return results;
        }

        IReadOnlyList<CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow> rows;
        try {
            rows = await QueryCertificateRowsAsync(
                BuildCrtShPostgreSqlConnectionString(options),
                CertificateInventoryCapture.BuildCrtShPostgreSqlDomainMetadataQuery(),
                new Dictionary<string, object?> {
                    ["domain"] = normalizedDomain,
                    ["hosts"] = normalizedHosts.ToArray(),
                    ["wildcardHosts"] = normalizedHosts.Select(CertificateInventoryCapture.BuildWildcardCandidateHost).ToArray(),
                    ["limit"] = Math.Min(Math.Max(32, normalizedHosts.Count * 8), 512)
                },
                cancellationToken).ConfigureAwait(false);
        } catch (DbaQueryExecutionException ex) {
            throw new InvalidOperationException("crt.sh PostgreSQL domain metadata query failed.", ex);
        }

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

    /// <summary>
    /// Builds a conservative crt.sh PostgreSQL domain-expansion query that returns DNS names only.
    /// </summary>
    public static string BuildDomainExpansionNamesQuery() {
        return
            """
            SELECT DISTINCT lower(candidate_name) AS dns_name
            FROM certificate c
            CROSS JOIN LATERAL (
                SELECT x509_commonName(c.certificate) AS candidate_name
                UNION
                SELECT alt_name
                FROM x509_altnames(c.certificate) AS alt_name
            ) AS candidate_names
            WHERE identities(c.certificate) @@ plainto_tsquery('simple', @domain)
              AND candidate_name IS NOT NULL
              AND (
                    lower(candidate_name) = lower(@domain)
                 OR lower(candidate_name) LIKE lower(@domainSuffix)
                  )
            ORDER BY dns_name
            LIMIT @limit;
            """;
    }

    /// <summary>
    /// Builds a conservative crt.sh PostgreSQL domain-tree certificate query.
    /// </summary>
    public static string BuildDomainTreeCertificateQuery() {
        return
            """
            WITH ranked_certificates AS (
                SELECT
                    c.id,
                    c.certificate,
                    (
                        SELECT MAX(ctle.entry_timestamp)
                        FROM ct_log_entry ctle
                        WHERE ctle.certificate_id = c.id
                    ) AS entry_timestamp,
                    x509_notBefore(c.certificate) AS not_before
                FROM certificate c
                WHERE identities(c.certificate) @@ plainto_tsquery('simple', @domain)
                  AND EXISTS (
                        SELECT 1
                        FROM (
                            SELECT lower(COALESCE(x509_commonName(c.certificate), '')) AS candidate_name
                            UNION
                            SELECT lower(alt_name)
                            FROM x509_altnames(c.certificate) AS alt_name
                        ) AS candidate_names
                        WHERE candidate_name = lower(@domain)
                           OR candidate_name LIKE lower(@domainSuffix)
                    )
                ORDER BY entry_timestamp DESC NULLS LAST,
                         not_before DESC NULLS LAST
                LIMIT @limit
            )
            SELECT
                rc.certificate,
                rc.entry_timestamp,
                x509_commonName(rc.certificate) AS common_name,
                x509_issuerName(rc.certificate) AS issuer_name,
                encode(x509_serialNumber(rc.certificate), 'hex') AS serial_number,
                rc.not_before,
                x509_notAfter(rc.certificate) AS not_after,
                ARRAY(
                    SELECT candidate_name
                    FROM (
                        SELECT x509_commonName(rc.certificate) AS candidate_name
                        UNION
                        SELECT alt_name
                        FROM x509_altnames(rc.certificate) AS alt_name
                    ) AS candidate_names
                    WHERE candidate_name IS NOT NULL
                    ORDER BY lower(candidate_name)
                ) AS dns_names
            FROM ranked_certificates rc
            ORDER BY rc.entry_timestamp DESC NULLS LAST,
                     rc.not_before DESC NULLS LAST;
            """;
    }

    /// <summary>
    /// Builds a crt.sh PostgreSQL certificate query for one host, including wildcard certificates that cover it.
    /// </summary>
    public static string BuildExactHostCertificateQuery() {
        return
            """
            WITH ranked_certificates AS (
                SELECT
                    c.id,
                    c.certificate,
                    (
                        SELECT MAX(ctle.entry_timestamp)
                        FROM ct_log_entry ctle
                        WHERE ctle.certificate_id = c.id
                    ) AS entry_timestamp,
                    x509_notBefore(c.certificate) AS not_before
                FROM certificate c
                WHERE (
                        identities(c.certificate) @@ plainto_tsquery('simple', @host)
                     OR identities(c.certificate) @@ plainto_tsquery('simple', @wildcardHost)
                      )
                  AND EXISTS (
                        SELECT 1
                        FROM (
                            SELECT lower(COALESCE(x509_commonName(c.certificate), '')) AS candidate_name
                            UNION
                            SELECT lower(alt_name)
                            FROM x509_altnames(c.certificate) AS alt_name
                        ) AS candidate_names
                        WHERE candidate_name = lower(@host)
                           OR candidate_name = lower(@wildcardHost)
                    )
                ORDER BY entry_timestamp DESC NULLS LAST,
                         not_before DESC NULLS LAST
                LIMIT @limit
            )
            SELECT
                rc.certificate,
                rc.entry_timestamp,
                x509_commonName(rc.certificate) AS common_name,
                x509_issuerName(rc.certificate) AS issuer_name,
                encode(x509_serialNumber(rc.certificate), 'hex') AS serial_number,
                rc.not_before,
                x509_notAfter(rc.certificate) AS not_after,
                ARRAY(
                    SELECT candidate_name
                    FROM (
                        SELECT x509_commonName(rc.certificate) AS candidate_name
                        UNION
                        SELECT alt_name
                        FROM x509_altnames(rc.certificate) AS alt_name
                    ) AS candidate_names
                    WHERE candidate_name IS NOT NULL
                    ORDER BY lower(candidate_name)
                ) AS dns_names
            FROM ranked_certificates rc
            ORDER BY rc.entry_timestamp DESC NULLS LAST,
                     rc.not_before DESC NULLS LAST;
            """;
    }

    /// <inheritdoc />
    public void Dispose() {
        _client.Dispose();
    }

    private async Task<CtCertificateQueryResult> QueryExactHostCertificatesAsync(
        CtCertificateQuery query,
        string normalizedHost,
        bool latestOnly,
        CancellationToken cancellationToken) {
        int limit = latestOnly
            ? Math.Min(ResolvePageSize(query, 1), DefaultExactLookupLimit)
            : ResolvePageSize(query, DefaultHistoryLimit);
        IReadOnlyList<CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow> rows = await QueryCertificateRowsAsync(
            BuildCrtShPostgreSqlConnectionString(_options),
            BuildExactHostCertificateQuery(),
            new Dictionary<string, object?> {
                ["host"] = normalizedHost,
                ["wildcardHost"] = CertificateInventoryCapture.BuildWildcardCandidateHost(normalizedHost),
                ["limit"] = limit
            },
            cancellationToken).ConfigureAwait(false);

        IEnumerable<CtCertificateRecord> records = rows
            .Where(row => row.CandidateNames.Any(candidate => CertificateInventoryCapture.CtMetadataCandidateMatchesHost(normalizedHost, candidate)))
            .Select(row => ToRecord(row))
            .Where(static record => record != null)
            .Select(static record => record!);
        if (latestOnly) {
            records = records.Take(1);
        }

        List<CtCertificateRecord> certificateRecords = records.ToList();
        return new CtCertificateQueryResult {
            ProviderId = ProviderId,
            Certificates = certificateRecords,
            DiscoveredNames = ExtractNames(certificateRecords),
            HasMore = false
        };
    }

    private async Task<CtCertificateQueryResult> QueryDomainExpansionAsync(
        CtCertificateQuery query,
        string normalizedDomain,
        CancellationToken cancellationToken) {
        if (query.RequireFullCertificate) {
            CtCertificateQueryResult certificateResult = await QueryDomainTreeCertificatesAsync(query, normalizedDomain, cancellationToken).ConfigureAwait(false);
            return new CtCertificateQueryResult {
                ProviderId = ProviderId,
                Certificates = certificateResult.Certificates,
                DiscoveredNames = certificateResult.DiscoveredNames,
                HasMore = false
            };
        }

        IReadOnlyList<string> names = await _client.QueryAsync(
            BuildCrtShPostgreSqlConnectionString(_options),
            BuildDomainExpansionNamesQuery(),
            MapName,
            new Dictionary<string, object?> {
                ["domain"] = normalizedDomain,
                ["domainSuffix"] = "%." + normalizedDomain,
                ["limit"] = ResolvePageSize(query, DefaultExpansionLimit)
            },
            cancellationToken).ConfigureAwait(false);

        return new CtCertificateQueryResult {
            ProviderId = ProviderId,
            DiscoveredNames = NormalizeNames(names),
            HasMore = false
        };
    }

    private async Task<CtCertificateQueryResult> QueryDomainTreeCertificatesAsync(
        CtCertificateQuery query,
        string normalizedDomain,
        CancellationToken cancellationToken) {
        IReadOnlyList<CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow> rows = await QueryCertificateRowsAsync(
            BuildCrtShPostgreSqlConnectionString(_options),
            BuildDomainTreeCertificateQuery(),
            new Dictionary<string, object?> {
                ["domain"] = normalizedDomain,
                ["domainSuffix"] = "%." + normalizedDomain,
                ["limit"] = ResolvePageSize(query, DefaultDomainTreeLimit)
            },
            cancellationToken).ConfigureAwait(false);

        List<CtCertificateRecord> certificates = rows
            .Select(row => ToRecord(row))
            .Where(static record => record != null)
            .Select(static record => record!)
            .ToList();
        return new CtCertificateQueryResult {
            ProviderId = ProviderId,
            Certificates = certificates,
            DiscoveredNames = ExtractNames(certificates),
            HasMore = false
        };
    }

    private Task<IReadOnlyList<CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow>> QueryCertificateRowsAsync(
        string connectionString,
        string query,
        IReadOnlyDictionary<string, object?> parameters,
        CancellationToken cancellationToken)
        => _client.QueryAsync(
            connectionString,
            query,
            MapRow,
            parameters,
            cancellationToken);

    private CtCertificateQueryResult WithProviderState(
        CtCertificateQueryResult result,
        CtProviderRuntimeState? runtimeState,
        CtProviderOutcomeKind outcomeKind,
        TimeSpan latency,
        string? error) {
        CtProviderRuntimeState providerState = CtProviderRuntimeStateUpdater.Apply(
            runtimeState,
            Profile,
            new CtProviderRequestOutcome {
                ProviderId = ProviderId,
                OutcomeKind = outcomeKind,
                OccurredAtUtc = DateTimeOffset.UtcNow,
                Latency = latency,
                Error = error
            });

        return new CtCertificateQueryResult {
            ProviderId = ProviderId,
            Certificates = result.Certificates,
            DiscoveredNames = result.DiscoveredNames,
            ContinuationToken = result.ContinuationToken,
            HasMore = result.HasMore,
            ProviderState = providerState,
            Diagnostics = result.Diagnostics
        };
    }

    private CancellationTokenSource CreateTimeoutTokenSource(CtCertificateQuery query, CancellationToken cancellationToken) {
        CancellationTokenSource source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        source.CancelAfter(ResolveTimeout(query));
        return source;
    }

    private TimeSpan ResolveTimeout(CtCertificateQuery query)
        => query.Timeout.HasValue && query.Timeout.Value > TimeSpan.Zero
            ? query.Timeout.Value
            : Profile.RateLimit.Normalize().RequestTimeout;

    private CtProviderQueryException CreateProviderQueryException(DbaQueryExecutionException exception) {
        string? providerErrorCode = TryGetProviderErrorCode(exception);
        string? transportFailureCode = TryGetTransportFailureCode(exception);
        string? effectiveErrorCode = providerErrorCode ?? transportFailureCode;
        CtProviderOutcomeKind outcomeKind = effectiveErrorCode switch {
            "40001" => CtProviderOutcomeKind.TransientFailure,
            "57014" => CtProviderOutcomeKind.Timeout,
            "57P03" => CtProviderOutcomeKind.TransientFailure,
            "53300" => CtProviderOutcomeKind.TransientFailure,
            "connect-timeout" => CtProviderOutcomeKind.TransientFailure,
            "network-unreachable" => CtProviderOutcomeKind.TransientFailure,
            "host-unreachable" => CtProviderOutcomeKind.TransientFailure,
            "connection-refused" => CtProviderOutcomeKind.TransientFailure,
            "host-not-found" => CtProviderOutcomeKind.TransientFailure,
            "connect-failure" => CtProviderOutcomeKind.TransientFailure,
            _ => CtProviderOutcomeKind.PermanentFailure
        };
        TimeSpan? retryAfter = outcomeKind == CtProviderOutcomeKind.RateLimited ||
                               outcomeKind == CtProviderOutcomeKind.TransientFailure
            ? Profile.RateLimit.Normalize().CooldownAfterRateLimit
            : null;
        string suffix = string.IsNullOrWhiteSpace(effectiveErrorCode)
            ? string.Empty
            : $" Provider code: {effectiveErrorCode}.";

        return new CtProviderQueryException(
            ProviderId,
            outcomeKind,
            "crt.sh PostgreSQL CT query failed." + suffix,
            exception,
            effectiveErrorCode,
            retryAfter);
    }

    private static string? TryGetProviderErrorCode(Exception exception) {
        for (Exception? current = exception; current != null; current = current.InnerException) {
            object? sqlState = current.GetType().GetProperty("SqlState")?.GetValue(current);
            if (sqlState is string value && !string.IsNullOrWhiteSpace(value)) {
                return value;
            }
        }

        return null;
    }

    private static string? TryGetTransportFailureCode(Exception exception) {
        for (Exception? current = exception; current != null; current = current.InnerException) {
            if (current is TimeoutException) {
                return "connect-timeout";
            }

            if (current is SocketException socketException) {
                string? code = socketException.SocketErrorCode switch {
                    SocketError.NetworkUnreachable => "network-unreachable",
                    SocketError.HostUnreachable => "host-unreachable",
                    SocketError.ConnectionRefused => "connection-refused",
                    SocketError.HostNotFound => "host-not-found",
                    SocketError.TimedOut => "connect-timeout",
                    _ => null
                };
                if (code != null) {
                    return code;
                }
            }
        }

        for (Exception? current = exception; current != null; current = current.InnerException) {
            // Keep this duck-typed so we can recognize transient connect failures from provider-specific
            // exceptions (for example Npgsql) without taking an additional package dependency here.
            object? isTransient = current.GetType().GetProperty("IsTransient")?.GetValue(current);
            if (isTransient is true) {
                string message = current.Message;
                if (message.IndexOf("Failed to connect", StringComparison.OrdinalIgnoreCase) >= 0) {
                    return "connect-failure";
                }
            }
        }

        return null;
    }

    private static int ResolvePageSize(CtCertificateQuery query, int defaultPageSize) {
        if (query.PageSize.HasValue && query.PageSize.Value > 0) {
            return query.PageSize.Value;
        }

        return defaultPageSize;
    }

    private static CtCertificateRecord? ToRecord(CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow row) {
        string? certificateParseDiagnostic = null;
        if (row.CertificateDer != null && row.CertificateDer.Length > 0) {
            try {
                return CtCertificateRecord.FromDer(
                    CtProviderProfiles.CrtShPostgreSqlProviderId,
                    row.CertificateDer,
                    providerCertificateId: row.SerialNumber,
                    entryTimestampUtc: row.EntryTimestampUtc);
            } catch (Exception ex) when (!ExceptionHelper.IsFatal(ex)) {
                certificateParseDiagnostic = "crt.sh PostgreSQL returned certificate DER that could not be parsed: " + ex.Message;
            }
        }

        return new CtCertificateRecord {
            ProviderId = CtProviderProfiles.CrtShPostgreSqlProviderId,
            ProviderCertificateId = row.SerialNumber,
            EntryTimestampUtc = row.EntryTimestampUtc,
            Subject = row.CommonName,
            Issuer = row.IssuerName,
            SerialNumber = row.SerialNumber,
            NotBeforeUtc = row.NotBeforeUtc,
            NotAfterUtc = row.NotAfterUtc,
            DnsNames = row.CandidateNames,
            CertificateDer = certificateParseDiagnostic == null ? row.CertificateDer : null,
            Diagnostics = certificateParseDiagnostic == null
                ? Array.Empty<string>()
                : new[] { certificateParseDiagnostic }
        };
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

    private static string MapName(IDataRecord row)
        => row.IsDBNull(0) ? string.Empty : row.GetString(0);

    private static string BuildCrtShPostgreSqlConnectionString(CertificateInventoryCaptureOptions options) {
        return BuildCrtShPostgreSqlConnectionString(options, null);
    }

    internal static string BuildCrtShPostgreSqlConnectionString(
        CertificateInventoryCaptureOptions? options,
        Func<string, IPAddress[]>? dnsResolver) {
        if (!string.IsNullOrWhiteSpace(options?.CrtShPostgreSqlConnectionString)) {
            return options!.CrtShPostgreSqlConnectionString!;
        }

        int timeoutSeconds = Math.Max(1, options?.CrtShPostgreSqlCommandTimeoutSeconds ?? 15);
        var builder = new DbConnectionStringBuilder {
            ConnectionString = PostgreSql.BuildConnectionString(
                host: ResolveCrtShPostgreSqlHost(dnsResolver),
                database: "certwatch",
                username: "guest",
                password: string.Empty,
                port: 5432,
                ssl: true)
        };
        builder["Timeout"] = timeoutSeconds;
        builder["Command Timeout"] = timeoutSeconds;
        return builder.ConnectionString;
    }

    internal static string ResolveCrtShPostgreSqlHost(Func<string, IPAddress[]>? dnsResolver = null) {
        try {
            IPAddress[] addresses = (dnsResolver ?? Dns.GetHostAddresses)(DefaultCrtShPostgreSqlHostName);
            IPAddress? ipv4Address = addresses.FirstOrDefault(static address => address.AddressFamily == AddressFamily.InterNetwork);
            if (ipv4Address != null) {
                return ipv4Address.ToString();
            }
        } catch (SocketException) {
            // Fall back to the pinned public IPv4 endpoint when DNS resolution is unavailable.
        } catch (ArgumentException) {
            // Fall back to the pinned public IPv4 endpoint when DNS resolution is unavailable.
        }

        return DefaultCrtShPostgreSqlPinnedIpv4Address;
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

    private static IReadOnlyList<string> ExtractNames(IEnumerable<CtCertificateRecord> records)
        => NormalizeNames(records.SelectMany(static record => record.DnsNames ?? Array.Empty<string>()));

    private static IReadOnlyList<string> NormalizeNames(IEnumerable<string> names)
        => names
            .Select(static name => NormalizeCtMetadataCandidate(name, preserveWildcard: true))
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Select(static name => name!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static string NormalizeHostOrDomain(string? value)
        => (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    private static string? NormalizeCtMetadataCandidate(string? value, bool preserveWildcard = false)
        => CertificateInventoryCapture.NormalizeCtMetadataCandidate(value, preserveWildcard);
}

internal interface ICrtShPostgreSqlQueryClient : IDisposable {
    Task<IReadOnlyList<T>> QueryAsync<T>(
        string connectionString,
        string query,
        Func<IDataRecord, T> map,
        IReadOnlyDictionary<string, object?> parameters,
        CancellationToken cancellationToken);
}

internal sealed class DbaClientXCrtShPostgreSqlQueryClient : ICrtShPostgreSqlQueryClient {
    private readonly PostgreSql _client = new();

    public async Task<IReadOnlyList<T>> QueryAsync<T>(
        string connectionString,
        string query,
        Func<IDataRecord, T> map,
        IReadOnlyDictionary<string, object?> parameters,
        CancellationToken cancellationToken) {
        IReadOnlyList<T> rows = await _client.QueryAsListAsync(
            connectionString,
            query,
            map,
            CopyParameters(parameters),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return rows;
    }

    private static Dictionary<string, object?>? CopyParameters(IReadOnlyDictionary<string, object?>? parameters) {
        if (parameters == null) {
            return null;
        }

        var copy = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, object?> parameter in parameters) {
            copy[parameter.Key] = parameter.Value;
        }

        return copy;
    }

    public void Dispose() {
        _client.Dispose();
    }
}

internal sealed class CrtShPostgreSqlMetadataProvider : ICtSqlMetadataProvider {
    private readonly CrtShPostgreSqlCertificateTransparencyProvider _provider = new();

    public Task<SubdomainDiscoveryEntry?> QueryExactMetadataAsync(
        string hostName,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        ISet<string>? targetedThumbprints,
        CancellationToken cancellationToken)
        => _provider.QueryExactMetadataAsync(hostName, options, logger, targetedThumbprints, cancellationToken);

    public Task<IReadOnlyDictionary<string, SubdomainDiscoveryEntry>> QueryDomainMetadataAsync(
        string domain,
        IReadOnlyCollection<string> hostNames,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        ISet<string>? targetedThumbprints,
        CancellationToken cancellationToken)
        => _provider.QueryDomainMetadataAsync(domain, hostNames, options, logger, targetedThumbprints, cancellationToken);

    public void Dispose() {
        _provider.Dispose();
    }
}
