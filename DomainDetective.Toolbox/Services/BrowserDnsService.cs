using DnsClientX;
using System.Diagnostics;
using System.Net.Http;

namespace DomainDetective.Toolbox.Services;

/// <summary>
/// Adapts browser HttpClient for use with DomainDetective's DomainHealthCheck.
/// Uses DNS-over-HTTPS JSON queries so browser tools avoid socket-based DNS APIs.
/// </summary>
public sealed class BrowserDnsService {
    private readonly HttpClient _httpClient;

    private static readonly IReadOnlyList<DohResolverProfile> _supportedResolvers = new[] {
        new DohResolverProfile("Google DNS", new Uri("https://dns.google/resolve"), "8.8.8.8", "Google"),
        new DohResolverProfile("Cloudflare DNS", new Uri("https://cloudflare-dns.com/dns-query"), "1.1.1.1", "Cloudflare")
    };

    public BrowserDnsService(HttpClient httpClient) {
        _httpClient = httpClient;
    }

    public static IReadOnlyList<DohResolverProfile> GetSupportedResolvers() {
        return _supportedResolvers;
    }

    public static string GetDefaultResolverName() {
        return _supportedResolvers[0].Name;
    }

    public static DohResolverProfile GetResolverProfile(string? resolverName) {
        return string.IsNullOrWhiteSpace(resolverName)
            ? _supportedResolvers[0]
            : _supportedResolvers.FirstOrDefault(resolver => string.Equals(resolver.Name, resolverName.Trim(), StringComparison.OrdinalIgnoreCase)) ?? _supportedResolvers[0];
    }

    public DomainHealthCheck CreateHealthCheck(string? resolverName = null) {
        var healthCheck = new DomainHealthCheck();
        var doh = new BrowserDohResolver(_httpClient, GetResolverProfile(resolverName));

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

        var doh = new BrowserDohResolver(_httpClient, GetResolverProfile(null));
        var recordTypes = (healthCheck.DnsPropagationRecordTypes != null && healthCheck.DnsPropagationRecordTypes.Length > 0)
            ? healthCheck.DnsPropagationRecordTypes.Distinct().ToArray()
            : new[] { DnsRecordType.A, DnsRecordType.AAAA };

        healthCheck.DnsPropagationSet.Reset(domainName);

        foreach (var recordType in recordTypes) {
            cancellationToken.ThrowIfCancellationRequested();

            var results = new List<DnsPropagationResult>(_supportedResolvers.Count);
            foreach (var resolver in _supportedResolvers) {
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
                } catch (DnsClientException ex) {
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
            report.Load(domainName, recordType, results, maxResultsToKeep: _supportedResolvers.Count);
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
        private readonly HttpClient _httpClient;
        private readonly DohResolverProfile _selectedResolver;

        public BrowserDohResolver(HttpClient httpClient, DohResolverProfile selectedResolver) {
            _httpClient = httpClient;
            _selectedResolver = selectedResolver;
        }

        public async Task<DnsAnswer[]> QueryAnswersAsync(string name, DnsRecordType type) {
            var response = await QueryResponseAsync(name, type, CancellationToken.None).ConfigureAwait(false);
            return response.Answers ?? Array.Empty<DnsAnswer>();
        }

        public Task<DnsResponse> QueryResponseAsync(string name, DnsRecordType type, CancellationToken cancellationToken) {
            return QueryResolverResponseAsync(_selectedResolver, name, type, cancellationToken);
        }

        public async Task<DnsResponse> QueryResolverResponseAsync(DohResolverProfile profile, string name, DnsRecordType type, CancellationToken cancellationToken) {
            return await DnsJsonQueryClient.QueryAsync(
                _httpClient, profile.QueryEndpoint, name, type, cancellationToken: cancellationToken).ConfigureAwait(false);
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

    }
}
