using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// CT provider that queries a DomainDetectiveCertificateTransparency API endpoint.
/// </summary>
public sealed class DdctApiCertificateTransparencyProvider : ICtCertificateTransparencyProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly HttpClient _httpClient;
    private readonly string _endpointUrl;
    private readonly string? _apiKey;
    private readonly string _apiKeyHeaderName;
    private readonly string? _scopeName;
    private readonly int _configuredQueryPageSize;
    private readonly int _maxPagesPerQuery;

    /// <summary>
    /// Creates a provider that uses a default shared <see cref="HttpClient"/>.
    /// </summary>
    public DdctApiCertificateTransparencyProvider()
        : this(SharedHttpClient.Instance, null)
    {
    }

    /// <summary>
    /// Creates a provider with a caller-supplied <see cref="HttpClient"/>.
    /// </summary>
    public DdctApiCertificateTransparencyProvider(HttpClient httpClient)
        : this(httpClient, null)
    {
    }

    /// <summary>
    /// Creates a provider with caller-supplied <see cref="HttpClient"/> and options.
    /// </summary>
    public DdctApiCertificateTransparencyProvider(
        HttpClient httpClient,
        DdctApiCertificateTransparencyProviderOptions? options)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        DdctApiCertificateTransparencyProviderOptions normalized = options ?? new DdctApiCertificateTransparencyProviderOptions();
        _endpointUrl = NormalizeEndpointUrl(normalized.EndpointUrl);
        string apiKey = normalized.ApiKey ?? string.Empty;
        _apiKey = string.IsNullOrWhiteSpace(apiKey) ? null : apiKey.Trim();
        string apiKeyHeaderName = normalized.ApiKeyHeaderName ?? string.Empty;
        _apiKeyHeaderName = string.IsNullOrWhiteSpace(apiKeyHeaderName)
            ? DdctApiCertificateTransparencyProviderOptions.DefaultApiKeyHeaderName
            : apiKeyHeaderName.Trim();
        string scopeName = normalized.ScopeName ?? string.Empty;
        _scopeName = string.IsNullOrWhiteSpace(scopeName) ? null : scopeName.Trim();
        _configuredQueryPageSize = ClampInt(
            normalized.QueryPageSize,
            1,
            DdctApiCertificateTransparencyProviderOptions.MaxQueryPageSize);
        _maxPagesPerQuery = ClampInt(
            normalized.MaxPagesPerQuery,
            1,
            DdctApiCertificateTransparencyProviderOptions.MaxAllowedPagesPerQuery);
        Profile = CtProviderProfiles.CreateDdctApi();
    }

    /// <inheritdoc />
    public string ProviderId => CtProviderProfiles.DdctApiProviderId;

    /// <inheritdoc />
    public CtProviderProfile Profile { get; }

    /// <inheritdoc />
    public async Task<CtCertificateQueryResult> QueryAsync(
        CtCertificateQuery query,
        CtProviderRuntimeState? runtimeState = null,
        CancellationToken cancellationToken = default)
    {
        CtCertificateQuery normalized = WithNormalizedName((query ?? throw new ArgumentNullException(nameof(query))).Normalize());
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (normalized.Timeout.HasValue)
        {
            timeout.CancelAfter(normalized.Timeout.Value);
        }

        return normalized.QueryKind switch
        {
            CtCertificateQueryKind.DomainExpansion => await QueryDomainExpansionAsync(normalized, timeout.Token).ConfigureAwait(false),
            CtCertificateQueryKind.ExactHostHistory => await QueryCertificatesAsync(normalized, includeSubdomains: false, ResolveRequestedCertificateCount(normalized), timeout.Token).ConfigureAwait(false),
            CtCertificateQueryKind.DomainTreeCertificates => await QueryCertificatesAsync(normalized, includeSubdomains: true, ResolveRequestedCertificateCount(normalized), timeout.Token).ConfigureAwait(false),
            _ => await QueryLatestCertificateAsync(normalized, timeout.Token).ConfigureAwait(false)
        };
    }

    private async Task<CtCertificateQueryResult> QueryLatestCertificateAsync(CtCertificateQuery query, CancellationToken cancellationToken)
    {
        DdctDomainSearchResponseDto response = await QueryDomainSearchAsync(query.Name, includeSubdomains: false, 1, 1, cancellationToken).ConfigureAwait(false);
        DdctCertificateSearchDto? latest = response.Certificates
            .OrderByDescending(static item => item.LastCtObservedAtUtc ?? item.FirstCtObservedAtUtc ?? item.LastIngestedByDdctAtUtc ?? DateTimeOffset.MinValue)
            .ThenByDescending(static item => item.NotAfterUtc ?? DateTimeOffset.MinValue)
            .FirstOrDefault();

        if (latest == null)
        {
            return new CtCertificateQueryResult
            {
                ProviderId = ProviderId,
                Certificates = Array.Empty<CtCertificateRecord>(),
                DiscoveredNames = response.Observations
                    .Select(static item => NormalizeHostName(item.MatchedName))
                    .Where(static name => name.Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                HasMore = false,
                ContinuationToken = null,
                Diagnostics = Array.Empty<string>()
            };
        }

        byte[] der = await DownloadCertificateDerAsync(latest.Sha256Fingerprint, cancellationToken).ConfigureAwait(false);
        return new CtCertificateQueryResult
        {
            ProviderId = ProviderId,
            Certificates = [
                CtCertificateRecord.FromDer(
                    ProviderId,
                    der,
                    providerCertificateId: latest.Sha256Fingerprint,
                    entryTimestampUtc: latest.LastCtObservedAtUtc ?? latest.FirstCtObservedAtUtc)
            ],
            DiscoveredNames = response.Certificates
                .Select(static item => NormalizeHostName(item.MatchedName))
                .Concat(response.Observations.Select(static item => NormalizeHostName(item.MatchedName)))
                .Where(static name => name.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            HasMore = false,
            ContinuationToken = null,
            Diagnostics = Array.Empty<string>()
        };
    }

    private async Task<CtCertificateQueryResult> QueryDomainExpansionAsync(CtCertificateQuery query, CancellationToken cancellationToken)
    {
        int pageSize = ResolvePageSize(query.PageSize);
        int offset = DecodeOffsetContinuation(query.ContinuationToken);
        DdctTimelineResponseDto page = await QueryTimelineAsync(
            query.Name,
            includeSubdomains: true,
            pageSize,
            offset,
            cancellationToken).ConfigureAwait(false);

        string[] names = page.Observations
            .Select(static item => NormalizeHostName(item.MatchedName))
            .Where(static name => name.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        bool hasMore = page.Observations.Count >= page.Limit && page.Limit > 0;

        return new CtCertificateQueryResult
        {
            ProviderId = ProviderId,
            DiscoveredNames = names,
            HasMore = hasMore,
            ContinuationToken = hasMore ? EncodeOffsetContinuation(offset + page.Observations.Count) : null,
            Diagnostics = Array.Empty<string>()
        };
    }

    private async Task<CtCertificateQueryResult> QueryCertificatesAsync(CtCertificateQuery query, bool includeSubdomains, int maxCertificates, CancellationToken cancellationToken)
    {
        int pageSize = ResolvePageSize(query.PageSize);
        int offset = DecodeOffsetContinuation(query.ContinuationToken);
        int currentOffset = offset;
        int maxPages = ResolveMaximumPageCount(pageSize, maxCertificates);
        bool hasMore = false;
        bool truncated = false;
        var discoveredNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var selectedObservations = new List<DdctObservationDto>(maxCertificates);
        var seenFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int pageIndex = 0; pageIndex < maxPages; pageIndex++)
        {
            DdctTimelineResponseDto page = await QueryTimelineAsync(
                query.Name,
                includeSubdomains,
                pageSize,
                currentOffset,
                cancellationToken).ConfigureAwait(false);
            if (page.Observations.Count == 0)
            {
                hasMore = false;
                break;
            }

            foreach (DdctObservationDto item in page.Observations)
            {
                string normalizedName = NormalizeHostName(item.MatchedName);
                if (normalizedName.Length > 0)
                {
                    discoveredNames.Add(normalizedName);
                }
            }

            foreach (DdctObservationDto item in page.Observations)
            {
                if (seenFingerprints.Add(item.Sha256Fingerprint))
                {
                    selectedObservations.Add(item);
                    if (selectedObservations.Count >= maxCertificates)
                    {
                        break;
                    }
                }
            }

            currentOffset += page.Observations.Count;
            bool pageHasMore = page.Observations.Count >= page.Limit && page.Limit > 0;
            hasMore = pageHasMore;

            if (selectedObservations.Count >= maxCertificates)
            {
                truncated = pageHasMore;
                break;
            }

            if (!pageHasMore)
            {
                break;
            }

            if (pageIndex == maxPages - 1)
            {
                truncated = true;
                break;
            }
        }

        var certificates = new List<CtCertificateRecord>(selectedObservations.Count);
        foreach (DdctObservationDto item in selectedObservations)
        {
            byte[] der = await DownloadCertificateDerAsync(item.Sha256Fingerprint, cancellationToken).ConfigureAwait(false);
            certificates.Add(CtCertificateRecord.FromDer(
                ProviderId,
                der,
                providerCertificateId: item.Sha256Fingerprint,
                entryTimestampUtc: item.CtObservedAtUtc));
        }

        return new CtCertificateQueryResult
        {
            ProviderId = ProviderId,
            Certificates = certificates,
            DiscoveredNames = discoveredNames
                .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            HasMore = hasMore,
            ContinuationToken = hasMore ? EncodeOffsetContinuation(currentOffset) : null,
            Diagnostics = BuildDiagnostics(truncated)
        };
    }

    private async Task<DdctTimelineResponseDto> QueryTimelineAsync(
        string name,
        bool includeSubdomains,
        int pageSize,
        int offset,
        CancellationToken cancellationToken)
    {
        string url = BuildTimelineUrl(name, includeSubdomains, pageSize, offset);
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, url, acceptJson: false);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new DdctTimelineResponseDto
            {
                Observations = Array.Empty<DdctObservationDto>(),
                Limit = pageSize,
                Offset = offset
            };
        }

        return await DeserializeJsonAsync<DdctTimelineResponseDto>(response, cancellationToken).ConfigureAwait(false);
    }

    private async Task<DdctDomainSearchResponseDto> QueryDomainSearchAsync(
        string name,
        bool includeSubdomains,
        int certificateLimit,
        int observationLimit,
        CancellationToken cancellationToken)
    {
        string url = BuildDomainSearchUrl(name, includeSubdomains, certificateLimit, observationLimit);
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, url, acceptJson: false);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new DdctDomainSearchResponseDto();
        }

        return await DeserializeJsonAsync<DdctDomainSearchResponseDto>(response, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<T> DeserializeJsonAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"DDCT API returned {(int)response.StatusCode} {response.ReasonPhrase}");
        }

        using Stream stream = await ReadContentStreamAsync(response.Content, cancellationToken).ConfigureAwait(false);
        T? payload = await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
        return payload ?? throw new InvalidOperationException("DDCT API returned an empty JSON payload.");
    }

    private async Task<byte[]> DownloadCertificateDerAsync(string sha256Fingerprint, CancellationToken cancellationToken)
    {
        string url = BuildPath("/api/v1/certificates/" + Uri.EscapeDataString(sha256Fingerprint) + "/der");
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, url, acceptJson: false);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            throw new InvalidOperationException("DDCT API did not have DER material for certificate " + sha256Fingerprint + ".");
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"DDCT DER endpoint returned {(int)response.StatusCode} {response.ReasonPhrase}");
        }

        return await ReadContentBytesAsync(response.Content, cancellationToken).ConfigureAwait(false);
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string url, bool acceptJson = true)
    {
        var request = new HttpRequestMessage(method, url);
        if (!string.IsNullOrWhiteSpace(_apiKey))
        {
            if (string.Equals(_apiKeyHeaderName, "Authorization", StringComparison.OrdinalIgnoreCase))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
            }
            else
            {
                request.Headers.TryAddWithoutValidation(_apiKeyHeaderName, _apiKey);
            }
        }

        if (acceptJson)
        {
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        return request;
    }

    private string BuildTimelineUrl(string name, bool includeSubdomains, int limit, int offset)
    {
        var query = new List<string>
        {
            "name=" + Uri.EscapeDataString(name),
            "includeSubdomains=" + (includeSubdomains ? "true" : "false"),
            "limit=" + limit.ToString(CultureInfo.InvariantCulture),
            "offset=" + offset.ToString(CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrWhiteSpace(_scopeName))
        {
            query.Add("scope=" + Uri.EscapeDataString(_scopeName));
        }

        return BuildPath("/api/v1/search/domain/timeline?" + string.Join("&", query));
    }

    private string BuildDomainSearchUrl(string name, bool includeSubdomains, int certificateLimit, int observationLimit)
    {
        var query = new List<string>
        {
            "name=" + Uri.EscapeDataString(name),
            "includeSubdomains=" + (includeSubdomains ? "true" : "false"),
            "certificateLimit=" + certificateLimit.ToString(CultureInfo.InvariantCulture),
            "observationLimit=" + observationLimit.ToString(CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrWhiteSpace(_scopeName))
        {
            query.Add("scope=" + Uri.EscapeDataString(_scopeName));
        }

        return BuildPath("/api/v1/search/domain?" + string.Join("&", query));
    }

    private string BuildPath(string relativePath)
        => _endpointUrl + relativePath;

    private int ResolvePageSize(int? requested)
        => ClampInt(
            requested.GetValueOrDefault(_configuredQueryPageSize),
            1,
            DdctApiCertificateTransparencyProviderOptions.MaxQueryPageSize);

    private int ResolveRequestedCertificateCount(CtCertificateQuery query)
        => ClampInt(
            query.PageSize.GetValueOrDefault(_configuredQueryPageSize),
            1,
            DdctApiCertificateTransparencyProviderOptions.MaxQueryPageSize);

    private static string NormalizeQueryName(string? value)
    {
        string normalized = NormalizeHostName(value);
        if (normalized.Length == 0)
        {
            throw new ArgumentException("CT query name must not be empty.", nameof(value));
        }

        return normalized;
    }

    private static CtCertificateQuery WithNormalizedName(CtCertificateQuery query)
        => new CtCertificateQuery
        {
            Name = NormalizeQueryName(query.Name),
            QueryKind = query.QueryKind,
            Operations = query.Operations,
            RequireFullCertificate = query.RequireFullCertificate,
            ContinuationToken = query.ContinuationToken,
            PageSize = query.PageSize,
            Timeout = query.Timeout
        };

    private int ResolveMaximumPageCount(int pageSize, int maxCertificates)
    {
        int pagesNeeded = (int)Math.Ceiling(Math.Max(maxCertificates, 1) / (double)Math.Max(pageSize, 1));
        return ClampInt(pagesNeeded, 1, _maxPagesPerQuery);
    }

    private static string EncodeOffsetContinuation(int offset)
        => Math.Max(0, offset).ToString(CultureInfo.InvariantCulture);

    private static int DecodeOffsetContinuation(string? continuation)
    {
        if (continuation == null)
        {
            return 0;
        }

        string trimmed = continuation.Trim();
        if (trimmed.Length == 0)
        {
            return 0;
        }

        return int.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value) && value > 0
            ? value
            : 0;
    }

    private static string NormalizeEndpointUrl(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? DdctApiCertificateTransparencyProviderOptions.DefaultEndpointUrl
            : value!.Trim().TrimEnd('/');

    private static string NormalizeHostName(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value!.Trim().TrimEnd('.').ToLowerInvariant();

    private static int ClampInt(int value, int minimum, int maximum)
        => value < minimum ? minimum : (value > maximum ? maximum : value);

    private static IReadOnlyList<string> BuildDiagnostics(bool truncated)
        => truncated ? new[] { "DDCT query reached the configured page cap before exhausting results." } : Array.Empty<string>();

    private static async Task<Stream> ReadContentStreamAsync(HttpContent content, CancellationToken cancellationToken)
    {
#if NET472
        cancellationToken.ThrowIfCancellationRequested();
        return await content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        return await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
    }

    private static async Task<byte[]> ReadContentBytesAsync(HttpContent content, CancellationToken cancellationToken)
    {
#if NET472
        cancellationToken.ThrowIfCancellationRequested();
        return await content.ReadAsByteArrayAsync().ConfigureAwait(false);
#else
        return await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
#endif
    }

    private sealed class DdctTimelineResponseDto
    {
        public IReadOnlyList<DdctObservationDto> Observations { get; init; } = Array.Empty<DdctObservationDto>();
        public int Limit { get; init; }
        public int Offset { get; init; }
    }

    private sealed class DdctDomainSearchResponseDto
    {
        public IReadOnlyList<DdctCertificateSearchDto> Certificates { get; init; } = Array.Empty<DdctCertificateSearchDto>();
        public IReadOnlyList<DdctObservationDto> Observations { get; init; } = Array.Empty<DdctObservationDto>();
    }

    private sealed class DdctCertificateSearchDto
    {
        public string Sha256Fingerprint { get; init; } = string.Empty;
        public DateTimeOffset? NotAfterUtc { get; init; }
        public DateTimeOffset? FirstCtObservedAtUtc { get; init; }
        public DateTimeOffset? LastCtObservedAtUtc { get; init; }
        public DateTimeOffset? LastIngestedByDdctAtUtc { get; init; }
        public string MatchedName { get; init; } = string.Empty;
    }

    private sealed class DdctObservationDto
    {
        public string ScopeName { get; init; } = string.Empty;
        public string MatchedName { get; init; } = string.Empty;
        public string Sha256Fingerprint { get; init; } = string.Empty;
        public string? Subject { get; init; }
        public string? Issuer { get; init; }
        public DateTimeOffset? NotBeforeUtc { get; init; }
        public DateTimeOffset? NotAfterUtc { get; init; }
        public DateTimeOffset? CtObservedAtUtc { get; init; }
        public DateTimeOffset? DdctRecordedAtUtc { get; init; }
        public long? CertificateAgeAtObservationSeconds { get; init; }
        public string? LogOperatorName { get; init; }
        public string LogUrl { get; init; } = string.Empty;
        public long EntryIndex { get; init; }
        public string EntryType { get; init; } = string.Empty;
        public bool IsPrecertificate { get; init; }
    }
}
