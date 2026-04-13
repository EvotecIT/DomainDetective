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
            _ => await QueryCertificatesAsync(normalized, includeSubdomains: false, 1, timeout.Token).ConfigureAwait(false)
        };
    }

    private async Task<CtCertificateQueryResult> QueryDomainExpansionAsync(CtCertificateQuery query, CancellationToken cancellationToken)
    {
        int pageSize = ResolvePageSize(query.PageSize);
        DdctPage<DdctObservationDto> page = await QueryObservationPagesAsync(
            query.Name,
            includeSubdomains: true,
            pageSize,
            query.ContinuationToken,
            cancellationToken).ConfigureAwait(false);

        string[] names = page.Items
            .Select(static item => NormalizeHostName(item.MatchedName))
            .Where(static name => name.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new CtCertificateQueryResult
        {
            ProviderId = ProviderId,
            DiscoveredNames = names,
            HasMore = page.HasMore,
            ContinuationToken = page.NextContinuation,
            Diagnostics = BuildDiagnostics(page.Truncated)
        };
    }

    private async Task<CtCertificateQueryResult> QueryCertificatesAsync(CtCertificateQuery query, bool includeSubdomains, int maxCertificates, CancellationToken cancellationToken)
    {
        int pageSize = ResolvePageSize(query.PageSize);
        DdctPage<DdctCertificateSearchDto> page = await QueryCertificatePagesAsync(
            query.Name,
            includeSubdomains,
            pageSize,
            maxCertificates,
            query.ContinuationToken,
            cancellationToken).ConfigureAwait(false);

        IEnumerable<DdctCertificateSearchDto> ordered = page.Items
            .OrderByDescending(static item => item.LastCtObservedAtUtc ?? item.FirstCtObservedAtUtc ?? item.LastIngestedByDdctAtUtc ?? DateTimeOffset.MinValue)
            .ThenByDescending(static item => item.NotAfterUtc ?? DateTimeOffset.MinValue);

        var certificates = new List<CtCertificateRecord>(maxCertificates);
        foreach (DdctCertificateSearchDto item in ordered.Take(maxCertificates))
        {
            byte[] der = await DownloadCertificateDerAsync(item.Sha256Fingerprint, cancellationToken).ConfigureAwait(false);
            certificates.Add(CtCertificateRecord.FromDer(
                ProviderId,
                der,
                providerCertificateId: item.Sha256Fingerprint,
                entryTimestampUtc: item.LastCtObservedAtUtc ?? item.FirstCtObservedAtUtc));
        }

        string[] discoveredNames = page.Items
            .Select(static item => NormalizeHostName(item.MatchedName))
            .Where(static name => name.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new CtCertificateQueryResult
        {
            ProviderId = ProviderId,
            Certificates = certificates,
            DiscoveredNames = discoveredNames,
            HasMore = page.HasMore,
            ContinuationToken = page.NextContinuation,
            Diagnostics = BuildDiagnostics(page.Truncated)
        };
    }

    private async Task<DdctPage<DdctCertificateSearchDto>> QueryCertificatePagesAsync(
        string name,
        bool includeSubdomains,
        int pageSize,
        int maxCertificates,
        string? continuation,
        CancellationToken cancellationToken)
    {
        var items = new List<DdctCertificateSearchDto>();
        string? currentContinuation = continuation;
        string? lastContinuation = continuation;
        int maxPages = ResolveMaximumPageCount(pageSize, maxCertificates);

        for (int pageIndex = 0; pageIndex < maxPages; pageIndex++)
        {
            string url = BuildPagedUrl("/api/v1/certificates/paged", name, includeSubdomains, pageSize, currentContinuation);
            DdctPageDto<DdctCertificateSearchDto> page = await SendPageAsync<DdctCertificateSearchDto>(url, cancellationToken).ConfigureAwait(false);
            if (page.Items.Count == 0)
            {
                return new DdctPage<DdctCertificateSearchDto>(items, page.Limit, page.Offset, null, false, false);
            }

            items.AddRange(page.Items);
            if (!page.HasMore || string.IsNullOrWhiteSpace(page.NextContinuation) || string.Equals(page.NextContinuation, lastContinuation, StringComparison.Ordinal))
            {
                return new DdctPage<DdctCertificateSearchDto>(items, page.Limit, page.Offset, page.NextContinuation, page.HasMore, false);
            }

            lastContinuation = currentContinuation = page.NextContinuation;
        }

        return new DdctPage<DdctCertificateSearchDto>(items, pageSize, 0, currentContinuation, true, true);
    }

    private async Task<DdctPage<DdctObservationDto>> QueryObservationPagesAsync(
        string name,
        bool includeSubdomains,
        int pageSize,
        string? continuation,
        CancellationToken cancellationToken)
    {
        var items = new List<DdctObservationDto>();
        string? currentContinuation = continuation;
        string? lastContinuation = continuation;

        for (int pageIndex = 0; pageIndex < _maxPagesPerQuery; pageIndex++)
        {
            string url = BuildPagedUrl("/api/v1/observations/paged", name, includeSubdomains, pageSize, currentContinuation);
            DdctPageDto<DdctObservationDto> page = await SendPageAsync<DdctObservationDto>(url, cancellationToken).ConfigureAwait(false);
            if (page.Items.Count == 0)
            {
                return new DdctPage<DdctObservationDto>(items, page.Limit, page.Offset, null, false, false);
            }

            items.AddRange(page.Items);
            if (!page.HasMore || string.IsNullOrWhiteSpace(page.NextContinuation) || string.Equals(page.NextContinuation, lastContinuation, StringComparison.Ordinal))
            {
                return new DdctPage<DdctObservationDto>(items, page.Limit, page.Offset, page.NextContinuation, page.HasMore, false);
            }

            lastContinuation = currentContinuation = page.NextContinuation;
        }

        return new DdctPage<DdctObservationDto>(items, pageSize, 0, currentContinuation, true, true);
    }

    private async Task<DdctPageDto<TItem>> SendPageAsync<TItem>(string url, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, url);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new DdctPageDto<TItem>
            {
                Items = Array.Empty<TItem>(),
                Limit = 0,
                Offset = 0,
                NextContinuation = null,
                HasMore = false
            };
        }

        return await DeserializeJsonAsync<DdctPageDto<TItem>>(response, cancellationToken).ConfigureAwait(false);
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
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, url);
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

    private HttpRequestMessage CreateRequest(HttpMethod method, string url)
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

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return request;
    }

    private string BuildPagedUrl(string relativePath, string name, bool includeSubdomains, int limit, string? continuation)
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

        return BuildPath(relativePath + "?" + string.Join("&", query));
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

    private sealed class DdctPage<TItem>
    {
        public DdctPage(IReadOnlyList<TItem> items, int limit, int offset, string? nextContinuation, bool hasMore, bool truncated)
        {
            Items = items;
            Limit = limit;
            Offset = offset;
            NextContinuation = nextContinuation;
            HasMore = hasMore;
            Truncated = truncated;
        }

        public IReadOnlyList<TItem> Items { get; }
        public int Limit { get; }
        public int Offset { get; }
        public string? NextContinuation { get; }
        public bool HasMore { get; }
        public bool Truncated { get; }
    }

    private sealed class DdctPageDto<TItem>
    {
        public IReadOnlyList<TItem> Items { get; init; } = Array.Empty<TItem>();
        public int Limit { get; init; }
        public int Offset { get; init; }
        public string? NextContinuation { get; init; }
        public bool HasMore { get; init; }
    }

    private sealed class DdctCertificateSearchDto
    {
        public string Sha256Fingerprint { get; init; } = string.Empty;
        public string? Sha1Thumbprint { get; init; }
        public string? SerialNumber { get; init; }
        public string? Subject { get; init; }
        public string? Issuer { get; init; }
        public DateTimeOffset? NotBeforeUtc { get; init; }
        public DateTimeOffset? NotAfterUtc { get; init; }
        public DateTimeOffset? FirstCtObservedAtUtc { get; init; }
        public DateTimeOffset? LastCtObservedAtUtc { get; init; }
        public DateTimeOffset? FirstIngestedByDdctAtUtc { get; init; }
        public DateTimeOffset? LastIngestedByDdctAtUtc { get; init; }
        public string MatchedName { get; init; } = string.Empty;
        public bool IsPrecertificate { get; init; }
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
