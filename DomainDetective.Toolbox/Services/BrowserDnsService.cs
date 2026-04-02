using DnsClientX;
using System.Diagnostics;
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
        healthCheck.DnsConfiguration.QueryDnsResponseOverride = doh.QueryResponseAsync;
        healthCheck.DnsInventoryAnalysis.QueryOverride = doh.QueryInventoryResponseAsync;
        healthCheck.NSAnalysis.QueryDnsFullOverride = doh.QueryFullAsync;
        healthCheck.DNSBLAnalysis.QueryDnsFullOverride = doh.QueryBatchAsync;
        healthCheck.DnsSecValidateLocally = false;
        healthCheck.NSAnalysis.EnableChaosFingerprinting = false;

        return healthCheck;
    }

    public async Task AnalyzeDnsPropagationAsync(DomainHealthCheck healthCheck, string domainName, CancellationToken cancellationToken = default) {
        if (healthCheck == null) {
            throw new ArgumentNullException(nameof(healthCheck));
        }

        if (string.IsNullOrWhiteSpace(domainName)) {
            throw new ArgumentNullException(nameof(domainName));
        }

        var doh = new BrowserDohResolver(_httpClient);
        var recordTypes = (healthCheck.DnsPropagationRecordTypes != null && healthCheck.DnsPropagationRecordTypes.Length > 0)
            ? healthCheck.DnsPropagationRecordTypes.Distinct().ToArray()
            : new[] { DnsRecordType.A, DnsRecordType.AAAA };

        healthCheck.DnsPropagationSet.Reset(domainName);

        foreach (var recordType in recordTypes) {
            cancellationToken.ThrowIfCancellationRequested();

            var results = new List<DnsPropagationResult>(BrowserDohResolver.PropagationResolvers.Count);
            foreach (var resolver in BrowserDohResolver.PropagationResolvers) {
                cancellationToken.ThrowIfCancellationRequested();

                var stopwatch = Stopwatch.StartNew();
                try {
                    var response = await doh.QueryResolverResponseAsync(resolver, domainName, recordType, cancellationToken).ConfigureAwait(false);
                    stopwatch.Stop();

                    var records = (response.Answers ?? Array.Empty<DnsAnswer>())
                        .Select(answer => answer.Data ?? answer.DataRaw)
                        .Where(value => !string.IsNullOrWhiteSpace(value))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();

                    results.Add(new DnsPropagationResult {
                        Server = resolver.Server,
                        RecordType = recordType,
                        Records = records,
                        Duration = stopwatch.Elapsed,
                        Success = response.Status == DnsResponseCode.NoError && records.Length > 0,
                        Error = response.Status == DnsResponseCode.NoError ? string.Empty : response.Status.ToString()
                    });
                } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                } catch (HttpRequestException ex) {
                    stopwatch.Stop();
                    results.Add(new DnsPropagationResult {
                        Server = resolver.Server,
                        RecordType = recordType,
                        Records = Array.Empty<string>(),
                        Duration = stopwatch.Elapsed,
                        Success = false,
                        Error = ex.Message
                    });
                } catch (TaskCanceledException ex) {
                    stopwatch.Stop();
                    results.Add(new DnsPropagationResult {
                        Server = resolver.Server,
                        RecordType = recordType,
                        Records = Array.Empty<string>(),
                        Duration = stopwatch.Elapsed,
                        Success = false,
                        Error = ex.Message
                    });
                } catch (JsonException ex) {
                    stopwatch.Stop();
                    results.Add(new DnsPropagationResult {
                        Server = resolver.Server,
                        RecordType = recordType,
                        Records = Array.Empty<string>(),
                        Duration = stopwatch.Elapsed,
                        Success = false,
                        Error = ex.Message
                    });
                } catch (InvalidOperationException ex) {
                    stopwatch.Stop();
                    results.Add(new DnsPropagationResult {
                        Server = resolver.Server,
                        RecordType = recordType,
                        Records = Array.Empty<string>(),
                        Duration = stopwatch.Elapsed,
                        Success = false,
                        Error = ex.Message
                    });
                }
            }

            var report = new DnsPropagationReportAnalysis();
            report.Load(domainName, recordType, results, maxResultsToKeep: BrowserDohResolver.PropagationResolvers.Count);
            healthCheck.DnsPropagationSet.Add(report);
        }
    }

    private sealed class BrowserHttpClientFactory : DomainDetective.IHttpClientFactory {
        private readonly HttpClient _client;

        public BrowserHttpClientFactory(HttpClient client) {
            _client = client;
        }

        public HttpClient CreateClient() {
            return _client;
        }
    }

    public sealed record DohResolverProfile(string Name, Uri QueryEndpoint, string Address, string Provider) {
        public PublicDnsEntry Server { get; } = new() {
            IPAddress = System.Net.IPAddress.Parse(Address),
            HostName = Name,
            ASN = string.Empty,
            ASNName = Provider,
            Enabled = true
        };
    }

    private sealed class BrowserDohResolver {
        private static readonly JsonSerializerOptions _jsonOptions = new() {
            PropertyNameCaseInsensitive = true
        };

        internal static readonly IReadOnlyList<DohResolverProfile> PropagationResolvers = new[] {
            new DohResolverProfile("Google DNS", new Uri("https://dns.google/resolve"), "8.8.8.8", "Google"),
            new DohResolverProfile("Cloudflare DNS", new Uri("https://cloudflare-dns.com/dns-query"), "1.1.1.1", "Cloudflare")
        };

        private readonly HttpClient _httpClient;

        public BrowserDohResolver(HttpClient httpClient) {
            _httpClient = httpClient;
        }

        public async Task<DnsAnswer[]> QueryAnswersAsync(string name, DnsRecordType type) {
            var response = await QueryResponseAsync(name, type, CancellationToken.None).ConfigureAwait(false);
            return response.Answers ?? Array.Empty<DnsAnswer>();
        }

        public Task<DnsResponse> QueryResponseAsync(string name, DnsRecordType type, CancellationToken cancellationToken) {
            return QueryResolverResponseAsync(PropagationResolvers[0], name, type, cancellationToken);
        }

        public async Task<DnsResponse> QueryResolverResponseAsync(DohResolverProfile profile, string name, DnsRecordType type, CancellationToken cancellationToken) {
            var normalizedName = NormalizeName(name);
            var separator = profile.QueryEndpoint.Query.Contains('?') ? "&" : "?";
            var requestUri = $"{profile.QueryEndpoint}{separator}name={Uri.EscapeDataString(normalizedName)}&type={(int)type}";
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Accept.ParseAdd("application/dns-json");

            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var payload = await JsonSerializer.DeserializeAsync<DohResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
            if (payload == null) {
                return EmptyResponse(DnsResponseCode.ServerFailure);
            }

            return new DnsResponse {
                Status = MapStatus(payload.Status),
                AuthenticData = payload.AD,
                Answers = MapAnswers(payload.Answer),
                Authorities = MapAnswers(payload.Authority),
                Additional = Array.Empty<DnsAnswer>()
            };
        }

        public Task<DnsResponse> QueryInventoryResponseAsync(string name, DnsRecordType type, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            return QueryResponseAsync(name, type, cancellationToken);
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
                responses.Add(await QueryResponseAsync(name, type, CancellationToken.None).ConfigureAwait(false));
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

        public bool AD { get; set; }

        public bool RA { get; set; }

        public bool RD { get; set; }

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
