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
        IReadOnlyList<DdctCertificateSearchDto> certificates = await QueryLatestCertificateCandidatesAsync(query.Name, cancellationToken).ConfigureAwait(false);
        DdctCertificateSearchDto? latest = certificates
            .OrderByDescending(static item => item.LastCtObservedAtUtc ?? item.FirstCtObservedAtUtc ?? item.LastIngestedByDdctAtUtc ?? DateTimeOffset.MinValue)
            .ThenByDescending(static item => item.NotAfterUtc ?? DateTimeOffset.MinValue)
            .FirstOrDefault();

        if (latest == null)
        {
            CtCertificateQueryResult? fallback = await TryQueryLatestCertificateViaDomainTreeAsync(query, cancellationToken).ConfigureAwait(false);
            if (fallback != null)
            {
                return fallback;
            }

            return CreateEmptyLatestResult();
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
            DiscoveredNames = certificates
                .Select(static item => CertificateTransparencyNameUtility.Normalize(item.MatchedName))
                .Where(static name => name.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            HasMore = false,
            ContinuationToken = null,
            Diagnostics = Array.Empty<string>()
        };
    }

    private async Task<CtCertificateQueryResult?> TryQueryLatestCertificateViaDomainTreeAsync(CtCertificateQuery query, CancellationToken cancellationToken)
    {
        string fallbackDomain = CertificateTransparencyNameUtility.GetRegistrableDomainOrSelf(query.Name);
        if (string.IsNullOrWhiteSpace(fallbackDomain) ||
            string.Equals(fallbackDomain, query.Name, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        int pageSize = ResolvePageSize(query.PageSize);
        string? continuation = query.ContinuationToken;
        bool truncated = false;
        var matchingNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        DdctObservationDto? latestMatch = null;

        for (int pageIndex = 0; pageIndex < _maxPagesPerQuery; pageIndex++)
        {
            DdctObservationPageDto page = await QueryObservationPageAsync(
                fallbackDomain,
                includeSubdomains: true,
                pageSize,
                continuation,
                cancellationToken).ConfigureAwait(false);

            if (page.Items.Count == 0)
            {
                break;
            }

            foreach (DdctObservationDto observation in page.Items)
            {
                string matchedName = CertificateTransparencyNameUtility.Normalize(observation.MatchedName);
                if (!CertificateTransparencyNameUtility.CertificateNameMatchesHost(query.Name, matchedName))
                {
                    continue;
                }

                if (matchedName.Length > 0)
                {
                    matchingNames.Add(matchedName);
                }

                // DDCT observation pages are ordered newest-first, so the first matching observation is the latest match.
                latestMatch ??= observation;
            }

            if (latestMatch != null)
            {
                break;
            }

            bool pageHasMore = HasMore(page);
            if (!pageHasMore)
            {
                break;
            }

            continuation = page.NextContinuation;
            if (pageIndex == _maxPagesPerQuery - 1)
            {
                truncated = true;
            }
        }

        if (latestMatch == null)
        {
            return truncated
                ? new CtCertificateQueryResult
                {
                    ProviderId = ProviderId,
                    Certificates = Array.Empty<CtCertificateRecord>(),
                    DiscoveredNames = Array.Empty<string>(),
                    HasMore = HasMore(continuation),
                    ContinuationToken = continuation,
                    Diagnostics = BuildDiagnostics(truncated)
                }
                : null;
        }

        byte[] der = await DownloadCertificateDerAsync(latestMatch.Sha256Fingerprint, cancellationToken).ConfigureAwait(false);
        return new CtCertificateQueryResult
        {
            ProviderId = ProviderId,
            Certificates = [
                CtCertificateRecord.FromDer(
                    ProviderId,
                    der,
                    providerCertificateId: latestMatch.Sha256Fingerprint,
                    entryTimestampUtc: latestMatch.CtObservedAtUtc)
            ],
            DiscoveredNames = matchingNames
                .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            HasMore = false,
            ContinuationToken = null,
            Diagnostics = BuildDiagnostics(truncated)
        };
    }

    private async Task<CtCertificateQueryResult> QueryDomainExpansionAsync(CtCertificateQuery query, CancellationToken cancellationToken)
    {
        int pageSize = ResolvePageSize(query.PageSize);
        DdctObservationPageDto page = await QueryObservationPageAsync(
            query.Name,
            includeSubdomains: true,
            pageSize,
            query.ContinuationToken,
            cancellationToken).ConfigureAwait(false);

        string[] names = page.Items
            .Select(static item => CertificateTransparencyNameUtility.Normalize(item.MatchedName))
            .Where(static name => name.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        bool hasMore = HasMore(page);

        return new CtCertificateQueryResult
        {
            ProviderId = ProviderId,
            DiscoveredNames = names,
            HasMore = hasMore,
            ContinuationToken = hasMore ? page.NextContinuation : null,
            Diagnostics = Array.Empty<string>()
        };
    }

    private async Task<CtCertificateQueryResult> QueryCertificatesAsync(CtCertificateQuery query, bool includeSubdomains, int maxCertificates, CancellationToken cancellationToken)
    {
        int pageSize = ResolvePageSize(query.PageSize);
        string? continuation = query.ContinuationToken;
        string? nextContinuation = null;
        int maxPages = ResolveMaximumPageCount(pageSize, maxCertificates);
        bool hasMore = false;
        bool truncated = false;
        var discoveredNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var selectedCertificates = new List<DdctCertificateSearchDto>(maxCertificates);
        var seenFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int pageIndex = 0; pageIndex < maxPages; pageIndex++)
        {
            DdctCertificatePageDto page = await QueryCertificatePageAsync(
                query.Name,
                includeSubdomains,
                pageSize,
                continuation,
                cancellationToken).ConfigureAwait(false);
            if (page.Items.Count == 0)
            {
                hasMore = false;
                break;
            }

            foreach (DdctCertificateSearchDto item in page.Items)
            {
                string normalizedName = CertificateTransparencyNameUtility.Normalize(item.MatchedName);
                if (normalizedName.Length > 0)
                {
                    discoveredNames.Add(normalizedName);
                }
            }

            foreach (DdctCertificateSearchDto item in page.Items)
            {
                if (seenFingerprints.Add(item.Sha256Fingerprint))
                {
                    selectedCertificates.Add(item);
                    if (selectedCertificates.Count >= maxCertificates)
                    {
                        break;
                    }
                }
            }

            hasMore = HasMore(page);
            nextContinuation = hasMore ? page.NextContinuation : null;

            if (selectedCertificates.Count >= maxCertificates)
            {
                truncated = hasMore;
                break;
            }

            if (!hasMore)
            {
                break;
            }

            continuation = page.NextContinuation;
            if (pageIndex == maxPages - 1)
            {
                truncated = true;
                break;
            }
        }

        var certificates = new List<CtCertificateRecord>(selectedCertificates.Count);
        foreach (DdctCertificateSearchDto item in selectedCertificates)
        {
            byte[] der = await DownloadCertificateDerAsync(item.Sha256Fingerprint, cancellationToken).ConfigureAwait(false);
            certificates.Add(CtCertificateRecord.FromDer(
                ProviderId,
                der,
                providerCertificateId: item.Sha256Fingerprint,
                entryTimestampUtc: item.LastCtObservedAtUtc ?? item.FirstCtObservedAtUtc));
        }

        return new CtCertificateQueryResult
        {
            ProviderId = ProviderId,
            Certificates = certificates,
            DiscoveredNames = discoveredNames
                .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            HasMore = hasMore,
            ContinuationToken = hasMore ? nextContinuation : null,
            Diagnostics = BuildDiagnostics(truncated)
        };
    }

    private async Task<DdctObservationPageDto> QueryObservationPageAsync(
        string name,
        bool includeSubdomains,
        int pageSize,
        string? continuation,
        CancellationToken cancellationToken)
    {
        string url = BuildObservationsPagedUrl(name, includeSubdomains, pageSize, continuation);
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, url, acceptJson: false);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new DdctObservationPageDto
            {
                Items = Array.Empty<DdctObservationDto>(),
                Limit = pageSize
            };
        }

        return await DeserializeJsonAsync<DdctObservationPageDto>(response, cancellationToken).ConfigureAwait(false);
    }

    private async Task<DdctCertificatePageDto> QueryCertificatePageAsync(
        string name,
        bool includeSubdomains,
        int pageSize,
        string? continuation,
        CancellationToken cancellationToken)
    {
        string url = BuildCertificatesPagedUrl(name, includeSubdomains, pageSize, continuation);
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, url, acceptJson: false);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new DdctCertificatePageDto
            {
                Items = Array.Empty<DdctCertificateSearchDto>(),
                Limit = pageSize
            };
        }

        return await DeserializeJsonAsync<DdctCertificatePageDto>(response, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<DdctCertificateSearchDto>> QueryLatestCertificateCandidatesAsync(string name, CancellationToken cancellationToken)
    {
        string url = BuildCertificatesUrl(name, includeSubdomains: false, limit: 1);
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, url, acceptJson: false);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return Array.Empty<DdctCertificateSearchDto>();
        }

        return await DeserializeJsonAsync<DdctCertificateSearchDto[]>(response, cancellationToken).ConfigureAwait(false);
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

    private string BuildCertificatesPagedUrl(string name, bool includeSubdomains, int limit, string? continuation)
    {
        var query = new List<string>
        {
            "name=" + Uri.EscapeDataString(name),
            "includeSubdomains=" + (includeSubdomains ? "true" : "false"),
            "limit=" + limit.ToString(CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrWhiteSpace(_scopeName))
        {
            query.Add("scope=" + Uri.EscapeDataString(_scopeName));
        }

        if (!string.IsNullOrWhiteSpace(continuation))
        {
            query.Add("continuation=" + Uri.EscapeDataString(continuation));
        }

        return BuildPath("/api/v1/certificates/paged?" + string.Join("&", query));
    }

    private string BuildCertificatesUrl(string name, bool includeSubdomains, int limit)
    {
        var query = new List<string>
        {
            "name=" + Uri.EscapeDataString(name),
            "includeSubdomains=" + (includeSubdomains ? "true" : "false"),
            "limit=" + limit.ToString(CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrWhiteSpace(_scopeName))
        {
            query.Add("scope=" + Uri.EscapeDataString(_scopeName));
        }

        return BuildPath("/api/v1/certificates?" + string.Join("&", query));
    }

    private string BuildObservationsPagedUrl(string name, bool includeSubdomains, int limit, string? continuation)
    {
        var query = new List<string>
        {
            "name=" + Uri.EscapeDataString(name),
            "includeSubdomains=" + (includeSubdomains ? "true" : "false"),
            "limit=" + limit.ToString(CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrWhiteSpace(_scopeName))
        {
            query.Add("scope=" + Uri.EscapeDataString(_scopeName));
        }

        if (!string.IsNullOrWhiteSpace(continuation))
        {
            query.Add("continuation=" + Uri.EscapeDataString(continuation));
        }

        return BuildPath("/api/v1/observations/paged?" + string.Join("&", query));
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
        string normalized = CertificateTransparencyNameUtility.Normalize(value);
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

    private static string NormalizeEndpointUrl(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? DdctApiCertificateTransparencyProviderOptions.DefaultEndpointUrl
            : value!.Trim().TrimEnd('/');

    private static CtCertificateQueryResult CreateEmptyLatestResult()
        => new()
        {
            ProviderId = ProviderIdStatic,
            Certificates = Array.Empty<CtCertificateRecord>(),
            DiscoveredNames = Array.Empty<string>(),
            HasMore = false,
            ContinuationToken = null,
            Diagnostics = Array.Empty<string>()
        };

    private const string ProviderIdStatic = CtProviderProfiles.DdctApiProviderId;

    private static bool HasMore<TItem>(DdctPageDto<TItem> page)
        => page.HasMore && !string.IsNullOrWhiteSpace(page.NextContinuation);

    private static bool HasMore(string? continuation)
        => !string.IsNullOrWhiteSpace(continuation);

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

    private abstract class DdctPageDto<TItem>
    {
        public IReadOnlyList<TItem> Items { get; init; } = Array.Empty<TItem>();
        public int Limit { get; init; }
        public string? NextContinuation { get; init; }
        public bool HasMore { get; init; }
    }

    private sealed class DdctCertificatePageDto : DdctPageDto<DdctCertificateSearchDto>
    {
    }

    private sealed class DdctObservationPageDto : DdctPageDto<DdctObservationDto>
    {
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
