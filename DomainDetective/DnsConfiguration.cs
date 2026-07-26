using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Configures DomainDetective DNS queries while delegating resolver behavior to DnsClientX.
    /// </summary>
    public class DnsConfiguration : IDisposable {
        internal const string DefaultUserAgent = "Mozilla/5.0";
        private readonly object _resolverGate = new();
        private ResolverEntry? _resolver;
        private string? _resolverKey;
        private bool _disposed;

        /// <summary>Gets or sets the User-Agent header for HTTP-based DNS transports.</summary>
        public string UserAgent { get; set; } = DefaultUserAgent;

        /// <summary>Gets or sets the optional per-client query concurrency cap.</summary>
        public int? ResolverMaxConcurrency { get; set; }

        /// <summary>Indicates that concurrency is enforced by the shared DnsClientX resolver.</summary>
        public bool SupportsResolverConcurrency => true;

        /// <summary>Gets or sets whether RFC-aware TTL response caching is enabled.</summary>
        public bool EnableResponseCache { get; set; }

        /// <summary>Gets or sets an optional upper bound for cached response lifetimes.</summary>
        public TimeSpan? MaxCacheTtl { get; set; }

        /// <summary>
        /// Gets or sets whether resolver transports are retained between operations. Standalone analyses
        /// leave this disabled; an owning host may enable reuse and dispose the configuration with its lifetime.
        /// </summary>
        public bool ReuseResolverClients { get; set; }

        /// <summary>Optional answer-only override used by tests and specialized consumers.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { get; set; }

        /// <summary>Optional full-response override used by tests and specialized consumers.</summary>
        public Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? QueryDnsResponseOverride { get; set; }

        /// <summary>Gets or sets the primary predefined DNS provider.</summary>
        public DnsEndpoint DnsEndpoint { get; set; }

        /// <summary>
        /// Gets explicitly configured providers. When non-empty, all concrete provider endpoints are
        /// expanded and queried according to <see cref="MultiResolverStrategy"/>.
        /// </summary>
        public List<DnsEndpoint> DnsEndpoints { get; } = new();

        /// <summary>Gets or sets the shared DnsClientX multi-resolver strategy.</summary>
        public MultiResolverStrategy MultiResolverStrategy { get; set; } = MultiResolverStrategy.FirstSuccess;

        /// <summary>Gets or sets the overall cap on concurrent endpoint requests. Null uses all configured endpoints.</summary>
        public int? MultiResolverMaxParallelism { get; set; }

        /// <summary>Gets or sets the selection behavior used for a single predefined provider.</summary>
        public DnsSelectionStrategy DnsSelectionStrategy { get; set; }

        /// <summary>Initializes configuration with the system DNS provider.</summary>
        public DnsConfiguration() : this(DnsEndpoint.System, DnsSelectionStrategy.First) { }

        /// <summary>Initializes configuration with a predefined DNS provider and selection behavior.</summary>
        public DnsConfiguration(DnsEndpoint dnsEndpoint, DnsSelectionStrategy dnsSelectionStrategy) {
            DnsEndpoint = dnsEndpoint;
            DnsSelectionStrategy = dnsSelectionStrategy;
        }

        /// <summary>Queries one name and applies an optional answer-data filter.</summary>
        public Task<DnsAnswer[]> QueryDNS(string name, DnsRecordType recordType, string filter = "", CancellationToken cancellationToken = default) {
            return QueryDNS(name, recordType, filter, includeAliasesInFilter: false, cancellationToken);
        }

        /// <summary>Queries one name and optionally preserves CNAME answers while filtering.</summary>
        public async Task<DnsAnswer[]> QueryDNS(string name, DnsRecordType recordType, string filter,
            bool includeAliasesInFilter, CancellationToken cancellationToken = default) {
            ValidateName(name, recordType);
            DnsResponse response = await QueryResponseAsync(name, recordType, cancellationToken).ConfigureAwait(false);
            return ApplyLocalFilter(response.Answers, filter, includeAliasesInFilter);
        }

        /// <summary>Queries multiple names and flattens their answer sets in input order.</summary>
        public Task<IEnumerable<DnsAnswer>> QueryDNS(string[] names, DnsRecordType recordType, string filter = "",
            CancellationToken cancellationToken = default) {
            return QueryDNS(names, recordType, filter, includeAliasesInFilter: false, cancellationToken);
        }

        /// <summary>Queries multiple names and flattens their filtered answer sets in input order.</summary>
        public async Task<IEnumerable<DnsAnswer>> QueryDNS(string[] names, DnsRecordType recordType, string filter,
            bool includeAliasesInFilter, CancellationToken cancellationToken = default) {
            ValidateNames(names, recordType);
            IReadOnlyList<DnsResponse?> responses = await QueryFullDNSOrdered(
                names, recordType, filter, includeAliasesInFilter, cancellationToken).ConfigureAwait(false);
            return responses.Where(response => response != null)
                .SelectMany(response => response!.Answers ?? Array.Empty<DnsAnswer>())
                .ToArray();
        }

        /// <summary>Queries multiple names and returns full responses in input order.</summary>
        public async Task<IEnumerable<DnsResponse>> QueryFullDNS(string[] names, DnsRecordType recordType,
            string filter = "", CancellationToken cancellationToken = default) {
            IReadOnlyList<DnsResponse?> responses = await QueryFullDNSOrdered(
                names, recordType, filter, includeAliasesInFilter: false, cancellationToken).ConfigureAwait(false);
            return responses.Where(response => response != null).Select(response => response!).ToArray();
        }

        /// <summary>Queries multiple names and retains one response slot per input name.</summary>
        public async Task<IReadOnlyList<DnsResponse?>> QueryFullDNSOrdered(string[] names, DnsRecordType recordType,
            string filter = "", bool includeAliasesInFilter = false, CancellationToken cancellationToken = default) {
            ValidateNames(names, recordType);
            cancellationToken.ThrowIfCancellationRequested();

            if (QueryDnsResponseOverride != null || QueryDnsOverride != null) {
                var overridden = new List<DnsResponse?>(names.Length);
                foreach (string name in names) {
                    cancellationToken.ThrowIfCancellationRequested();
                    DnsResponse response = await QueryResponseAsync(name, recordType, cancellationToken).ConfigureAwait(false);
                    overridden.Add(ApplyLocalFilter(response, filter, includeAliasesInFilter));
                }
                return overridden;
            }

            using ResolverLease lease = AcquireResolver();
            DnsResponse[] responses = await lease.Resolver.QueryBatchAsync(names, recordType, cancellationToken).ConfigureAwait(false);
            var projected = new DnsResponse?[names.Length];
            for (int i = 0; i < names.Length; i++) {
                DnsResponse response = i < responses.Length
                    ? responses[i]
                    : CreateErrorResponse(names[i], recordType, "The shared resolver returned no response for this input.");
                projected[i] = ApplyLocalFilter(response, filter, includeAliasesInFilter);
            }
            return projected;
        }

        /// <summary>Queries multiple names and returns DomainDetective's per-name summary contract.</summary>
        public async Task<IReadOnlyList<DnsQueryBatchResult>> QueryDNSBatch(string[] names, DnsRecordType recordType,
            string filter = "", bool includeAliasesInFilter = false, CancellationToken cancellationToken = default) {
            ValidateNames(names, recordType);
            IReadOnlyList<DnsResponse?> responses = await QueryFullDNSOrdered(
                names, recordType, filter, includeAliasesInFilter, cancellationToken).ConfigureAwait(false);
            var results = new List<DnsQueryBatchResult>(names.Length);
            for (int i = 0; i < names.Length; i++) {
                DnsResponse? response = i < responses.Count ? responses[i] : null;
                DnsAnswer[] answers = response?.Answers ?? Array.Empty<DnsAnswer>();
                DnsResponseCode code = response?.Status ?? DnsResponseCode.ServerFailure;
                results.Add(new DnsQueryBatchResult {
                    Name = names[i],
                    RecordType = recordType,
                    ResponseCode = code,
                    Answers = answers,
                    QuerySucceeded = code == DnsResponseCode.NoError && string.IsNullOrEmpty(response?.Error) && answers.Length > 0
                });
            }
            return results;
        }

        private async Task<DnsResponse> QueryResponseAsync(string name, DnsRecordType recordType, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            if (QueryDnsResponseOverride != null) {
                DnsResponse response = await QueryDnsResponseOverride(name, recordType, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                return response ?? CreateErrorResponse(name, recordType, "The DNS response override returned null.");
            }
            if (QueryDnsOverride != null) {
                DnsAnswer[] answers = await QueryDnsOverride(name, recordType).ConfigureAwait(false) ?? Array.Empty<DnsAnswer>();
                cancellationToken.ThrowIfCancellationRequested();
                return new DnsResponse {
                    Status = DnsResponseCode.NoError,
                    Questions = new[] { new DnsQuestion { Name = name, OriginalName = name, Type = recordType } },
                    Answers = answers,
                    Authorities = Array.Empty<DnsAnswer>(),
                    Additional = Array.Empty<DnsAnswer>()
                };
            }

            using ResolverLease lease = AcquireResolver();
            return await lease.Resolver.QueryAsync(name, recordType, cancellationToken).ConfigureAwait(false);
        }

        private ResolverLease AcquireResolver() {
            if (_disposed) throw new ObjectDisposedException(nameof(DnsConfiguration));
            DnsEndpoint[] providers = DnsEndpoints.Count > 0 ? DnsEndpoints.ToArray() : new[] { DnsEndpoint };
            DnsResolverEndpoint[] endpoints = DnsResolverEndpointFactory.From(providers);
            if (endpoints.Length == 0) {
                throw new InvalidOperationException($"DNS provider '{string.Join(", ", providers)}' does not expose a supported resolver endpoint.");
            }

            MultiResolverStrategy strategy = GetEffectiveMultiResolverStrategy();
            int parallelism = GetEffectiveMultiResolverMaxParallelism(endpoints.Length);
            var options = new MultiResolverOptions {
                Strategy = strategy,
                MaxParallelism = parallelism,
                MaxConcurrency = ResolverMaxConcurrency,
                UserAgent = UserAgent,
                EnableResponseCache = EnableResponseCache,
                MaxCacheTtl = MaxCacheTtl,
                UseTcpFallback = true
            };
            string key = string.Join("|", endpoints.Select(endpoint =>
                $"{endpoint.Transport}:{endpoint.RequestFormat}:{endpoint.Host}:{endpoint.Port}:{endpoint.DohUrl}:" +
                $"{endpoint.Family}:{endpoint.TlsServerName}:{endpoint.Timeout}:{endpoint.AllowTcpFallback}:" +
                $"{endpoint.EdnsBufferSize}:{endpoint.DnsSecOk}")) +
                $"|{strategy}|{parallelism}|{ResolverMaxConcurrency}|{UserAgent}|{EnableResponseCache}|{MaxCacheTtl}";
            lock (_resolverGate) {
                if (_disposed) throw new ObjectDisposedException(nameof(DnsConfiguration));
                if (!ReuseResolverClients) {
                    RetireResolver(_resolver);
                    _resolver = null;
                    _resolverKey = null;
                    var transient = new ResolverEntry(new DnsMultiResolver(endpoints, options)) {
                        ActiveLeases = 1,
                        Retired = true
                    };
                    return new ResolverLease(this, transient);
                }
                if (_resolver == null || !string.Equals(_resolverKey, key, StringComparison.Ordinal)) {
                    RetireResolver(_resolver);
                    _resolver = new ResolverEntry(new DnsMultiResolver(endpoints, options));
                    _resolverKey = key;
                }
                _resolver.ActiveLeases++;
                return new ResolverLease(this, _resolver);
            }
        }

        /// <summary>Resolves the DnsClientX strategy represented by this configuration.</summary>
        internal MultiResolverStrategy GetEffectiveMultiResolverStrategy() {
            return DnsEndpoints.Count > 0
                ? MultiResolverStrategy
                : DnsSelectionStrategy == DnsSelectionStrategy.Random
                    ? MultiResolverStrategy.Random
                    : MultiResolverStrategy.SequentialFallback;
        }

        /// <summary>Resolves the endpoint concurrency cap represented by this configuration.</summary>
        internal int GetEffectiveMultiResolverMaxParallelism(int endpointCount) {
            return Math.Max(1, MultiResolverMaxParallelism ?? endpointCount);
        }

        private void ReleaseResolver(ResolverEntry entry) {
            lock (_resolverGate) {
                entry.ActiveLeases--;
                if (entry.Retired && entry.ActiveLeases == 0) entry.Resolver.Dispose();
            }
        }

        private static void RetireResolver(ResolverEntry? entry) {
            if (entry == null || entry.Retired) return;
            entry.Retired = true;
            if (entry.ActiveLeases == 0) entry.Resolver.Dispose();
        }

        /// <summary>Disposes the reusable resolver and its transport clients.</summary>
        public void Dispose() {
            lock (_resolverGate) {
                if (_disposed) return;
                _disposed = true;
                RetireResolver(_resolver);
                _resolver = null;
                _resolverKey = null;
            }
        }

        private sealed class ResolverEntry {
            internal ResolverEntry(DnsMultiResolver resolver) {
                Resolver = resolver;
            }

            internal DnsMultiResolver Resolver { get; }
            internal int ActiveLeases { get; set; }
            internal bool Retired { get; set; }
        }

        private sealed class ResolverLease : IDisposable {
            private DnsConfiguration? _owner;
            private readonly ResolverEntry _entry;

            internal ResolverLease(DnsConfiguration owner, ResolverEntry entry) {
                _owner = owner;
                _entry = entry;
            }

            internal DnsMultiResolver Resolver => _entry.Resolver;

            public void Dispose() {
                DnsConfiguration? owner = Interlocked.Exchange(ref _owner, null);
                owner?.ReleaseResolver(_entry);
            }
        }

        private static DnsResponse ApplyLocalFilter(DnsResponse response, string filter, bool includeAliasesInFilter) {
            if (string.IsNullOrEmpty(filter)) return response;
            return response.WithAnswers(ApplyLocalFilter(response.Answers, filter, includeAliasesInFilter));
        }

        private static DnsAnswer[] ApplyLocalFilter(DnsAnswer[]? answers, string filter, bool includeAliasesInFilter) {
            if (answers == null || answers.Length == 0) return Array.Empty<DnsAnswer>();
            if (string.IsNullOrEmpty(filter)) return answers;
            return answers.Where(answer =>
                    includeAliasesInFilter && answer.Type == DnsRecordType.CNAME ||
                    (answer.DataRaw ?? answer.Data ?? string.Empty).IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToArray();
        }

        private static DnsResponse CreateErrorResponse(string name, DnsRecordType recordType, string error) {
            return new DnsResponse {
                Status = DnsResponseCode.ServerFailure,
                Error = error,
                Questions = new[] { new DnsQuestion { Name = name, OriginalName = name, Type = recordType } },
                Answers = Array.Empty<DnsAnswer>(),
                Authorities = Array.Empty<DnsAnswer>(),
                Additional = Array.Empty<DnsAnswer>()
            };
        }

        private static void ValidateName(string name, DnsRecordType recordType) {
            if (string.IsNullOrWhiteSpace(name)) {
                throw new ArgumentNullException(nameof(name), $"Domain name cannot be null or empty when querying {recordType} records.");
            }
        }

        private static void ValidateNames(string[] names, DnsRecordType recordType) {
            if (names == null || names.Length == 0) {
                throw new ArgumentNullException(nameof(names), $"No domain names provided for querying {recordType} records.");
            }
            foreach (string name in names) ValidateName(name, recordType);
        }
    }
}
