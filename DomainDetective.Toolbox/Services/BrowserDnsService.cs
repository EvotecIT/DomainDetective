using DnsClientX;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective.Toolbox.Services;

/// <summary>
/// Adapts browser HttpClient for use with DomainDetective's DomainHealthCheck.
/// Uses DNS-over-HTTPS JSON queries so browser tools avoid socket-based DNS APIs.
/// </summary>
public sealed class BrowserDnsService {
    private readonly HttpClient _httpClient;

    public BrowserDnsService(HttpClient httpClient) {
        _httpClient = httpClient;
    }

    public DomainHealthCheck CreateHealthCheck() {
        var healthCheck = new DomainHealthCheck();
        var doh = new BrowserDohResolver(_httpClient);

        healthCheck.HttpClientFactory = new BrowserHttpClientFactory(_httpClient);
        healthCheck.DnsConfiguration.QueryDnsOverride = doh.QueryAnswersAsync;
        healthCheck.DnsInventoryAnalysis.QueryOverride = doh.QueryInventoryResponseAsync;
        healthCheck.NSAnalysis.QueryDnsFullOverride = doh.QueryFullAsync;
        healthCheck.DNSBLAnalysis.QueryDnsFullOverride = doh.QueryBatchAsync;
        healthCheck.NSAnalysis.EnableChaosFingerprinting = false;

        return healthCheck;
    }

    private sealed class BrowserHttpClientFactory : DomainDetective.IHttpClientFactory {
        private readonly HttpClient _client;

        public BrowserHttpClientFactory(HttpClient client) {
            _client = client;
        }

        public HttpClient CreateClient() => _client;
    }

    private sealed class BrowserDohResolver {
        private static readonly JsonSerializerOptions _jsonOptions = new() {
            PropertyNameCaseInsensitive = true
        };

        private readonly HttpClient _httpClient;

        public BrowserDohResolver(HttpClient httpClient) {
            _httpClient = httpClient;
        }

        public async Task<DnsAnswer[]> QueryAnswersAsync(string name, DnsRecordType type) {
            var response = await QueryResponseAsync(name, type).ConfigureAwait(false);
            return response.Answers ?? Array.Empty<DnsAnswer>();
        }

        public async Task<DnsResponse> QueryResponseAsync(string name, DnsRecordType type) {
            var normalizedName = NormalizeName(name);
            var requestUri = $"https://dns.google/resolve?name={Uri.EscapeDataString(normalizedName)}&type={(int)type}";
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            var payload = await JsonSerializer.DeserializeAsync<DohResponse>(stream, _jsonOptions).ConfigureAwait(false);
            if (payload == null) {
                return EmptyResponse(DnsResponseCode.ServerFailure);
            }

            return new DnsResponse {
                Status = MapStatus(payload.Status),
                Answers = MapAnswers(payload.Answer),
                Authorities = MapAnswers(payload.Authority),
                Additional = Array.Empty<DnsAnswer>()
            };
        }

        public Task<DnsResponse> QueryInventoryResponseAsync(string name, DnsRecordType type, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            return QueryResponseAsync(name, type);
        }

        public Task<IEnumerable<DnsResponse>> QueryFullAsync(string name, DnsRecordType type) {
            return QueryBatchAsync(new[] { name }, type);
        }

        public async Task<IEnumerable<DnsResponse>> QueryBatchAsync(string[] names, DnsRecordType type) {
            if (names == null || names.Length == 0) {
                return Array.Empty<DnsResponse>();
            }

            var responses = new List<DnsResponse>(names.Length);
            foreach (var name in names) {
                responses.Add(await QueryResponseAsync(name, type).ConfigureAwait(false));
            }
            return responses;
        }

        private static DnsResponse EmptyResponse(DnsResponseCode status) {
            return new DnsResponse {
                Status = status,
                Answers = Array.Empty<DnsAnswer>(),
                Authorities = Array.Empty<DnsAnswer>(),
                Additional = Array.Empty<DnsAnswer>()
            };
        }

        private static string NormalizeName(string name) {
            return (name ?? string.Empty).Trim().TrimEnd('.');
        }

        private static DnsAnswer[] MapAnswers(DohAnswer[]? answers) {
            if (answers == null || answers.Length == 0) {
                return Array.Empty<DnsAnswer>();
            }

            var mapped = new List<DnsAnswer>(answers.Length);
            foreach (var answer in answers) {
                if (!TryMapRecordType(answer.Type, out var recordType)) {
                    continue;
                }

                mapped.Add(new DnsAnswer {
                    Name = answer.Name ?? string.Empty,
                    Type = recordType,
                    TTL = answer.Ttl,
                    DataRaw = answer.Data ?? string.Empty
                });
            }

            return mapped.ToArray();
        }

        private static bool TryMapRecordType(int type, out DnsRecordType recordType) {
            if (type >= ushort.MinValue && type <= ushort.MaxValue && Enum.IsDefined(typeof(DnsRecordType), (ushort)type)) {
                recordType = (DnsRecordType)(ushort)type;
                return true;
            }

            recordType = default;
            return false;
        }

        private static DnsResponseCode MapStatus(int status) {
            return status >= byte.MinValue && status <= byte.MaxValue && Enum.IsDefined(typeof(DnsResponseCode), (byte)status)
                ? (DnsResponseCode)(byte)status
                : DnsResponseCode.ServerFailure;
        }
    }

    private sealed class DohResponse {
        public int Status { get; set; }

        public DohAnswer[]? Answer { get; set; }

        public DohAnswer[]? Authority { get; set; }
    }

    private sealed class DohAnswer {
        public string? Name { get; set; }

        public int Type { get; set; }

        [JsonPropertyName("TTL")]
        public int Ttl { get; set; }

        public string? Data { get; set; }
    }
}
