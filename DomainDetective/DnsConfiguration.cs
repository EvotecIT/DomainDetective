using DnsClientX;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Represents the configuration for DNS queries.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// This configuration object controls which DNS servers are queried
    /// as well as the strategy used when multiple endpoints are defined.
    /// </remarks>
    public class DnsConfiguration {
        internal const string DefaultUserAgent = "Mozilla/5.0";
        /// <summary>
        /// Gets or sets the default User-Agent header for DNS queries.
        /// </summary>
        public string UserAgent { get; set; } = DefaultUserAgent;
        /// <summary>
        /// Optional maximum concurrency for DNS queries passed to the underlying resolver.
        /// Applied when supported by the DnsClientX version.
        /// </summary>
        public int? ResolverMaxConcurrency { get; set; }
        /// <summary>
        /// Indicates whether the underlying resolver supports a concurrency hint.
        /// </summary>
        public bool SupportsResolverConcurrency => true;
        /// <summary>Optional override for DNS queries.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { get; set; }
        /// <summary>
        /// Gets or sets the primary DNS endpoint.
        /// </summary>
        public DnsEndpoint DnsEndpoint { get; set; }

        /// <summary>
        /// Optional multi-resolver list. When non-empty, queries will use this list according to <see cref="MultiResolverStrategy"/>.
        /// </summary>
        public List<DnsEndpoint> DnsEndpoints { get; } = new();

        /// <summary>Strategy used when <see cref="DnsEndpoints"/> contains multiple endpoints.</summary>
        public MultiResolverStrategy MultiResolverStrategy { get; set; } = MultiResolverStrategy.FirstSuccess;

        /// <summary>Maximum number of endpoints to query in parallel (null means all).</summary>
        public int? MultiResolverMaxParallelism { get; set; }

        /// <summary>
        /// Gets or sets the DNS selection strategy.
        /// </summary>
        public DnsSelectionStrategy DnsSelectionStrategy { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DnsConfiguration"/> class with default values using the system DNS endpoint.
        /// </summary>
        public DnsConfiguration() {
            DnsEndpoint = DnsEndpoint.System;
            DnsSelectionStrategy = DnsSelectionStrategy.First;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DnsConfiguration"/> class with specified values.
        /// </summary>
        public DnsConfiguration(DnsEndpoint dnsEndpoint, DnsSelectionStrategy dnsSelectionStrategy) {
            DnsEndpoint = dnsEndpoint;
            DnsSelectionStrategy = dnsSelectionStrategy;
        }

        /// <summary>
        /// Queries the DNS for a specific name and record type, optionally applying a filter.
        /// </summary>
        public Task<DnsAnswer[]> QueryDNS(string name, DnsRecordType recordType, string filter = "", CancellationToken cancellationToken = default) {
            return QueryDNS(name, recordType, filter, includeAliasesInFilter: false, cancellationToken);
        }

        /// <summary>
        /// Queries the DNS for a specific name and record type, optionally applying a filter.
        /// </summary>
        public async Task<DnsAnswer[]> QueryDNS(string name, DnsRecordType recordType, string filter, bool includeAliasesInFilter, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentNullException(nameof(name), $"Domain name cannot be null or empty when querying {recordType} records.");
            }
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, recordType);
            }
            var filterOptions = includeAliasesInFilter ? new ResolveFilterOptions(true) : new ResolveFilterOptions();
            try {
                // Multi-resolver path
                if (DnsEndpoints.Count > 0) {
                    var answers = await ResolveWithEndpoints(name, recordType, filter, includeAliasesInFilter, DnsEndpoints.ToArray(), MultiResolverStrategy, MultiResolverMaxParallelism, cancellationToken).ConfigureAwait(false);
                    if (answers.Length > 0) return answers;
                }
                using var client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
                client.EndpointConfiguration.UserAgent = UserAgent;
                if (ResolverMaxConcurrency.HasValue) {
                    client.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
                }
                if (filter != string.Empty || includeAliasesInFilter) {
                    var data = await client.ResolveFilter(name, recordType, filter, filterOptions);
                    return data.Answers;
                }

                var result = await client.Resolve(name, recordType);
                return result.Answers;
            } catch (Exception ex) when (ex is TaskCanceledException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException) {
                // Transient DNS/network error: try a conservative fallback endpoint, then return empty if it still fails.
                var fallbacks = GetFallbackEndpoints(DnsEndpoint);
                foreach (var fb in fallbacks) {
                    cancellationToken.ThrowIfCancellationRequested();
                    try {
                        using var clientFb = new ClientX(endpoint: fb, DnsSelectionStrategy);
                        clientFb.EndpointConfiguration.UserAgent = UserAgent;
                        if (ResolverMaxConcurrency.HasValue) {
                            clientFb.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
                        }
                        if (filter != string.Empty || includeAliasesInFilter) {
                            var dataFb = await clientFb.ResolveFilter(name, recordType, filter, filterOptions);
                            return dataFb.Answers;
                        }
                        var resFb = await clientFb.Resolve(name, recordType);
                        return resFb.Answers;
                    } catch (Exception retryEx) when (retryEx is TaskCanceledException || retryEx is TimeoutException || retryEx is System.Net.Http.HttpRequestException) {
                        // try next fallback
                    }
                }
                return Array.Empty<DnsAnswer>();
            }
        }

        /// <summary>
        /// Queries the DNS for a list of names and a record type, optionally applying a filter.
        /// </summary>
        public Task<IEnumerable<DnsAnswer>> QueryDNS(string[] names, DnsRecordType recordType, string filter = "", CancellationToken cancellationToken = default) {
            return QueryDNS(names, recordType, filter, includeAliasesInFilter: false, cancellationToken);
        }

        /// <summary>
        /// Queries the DNS for a list of names and a record type, optionally applying a filter.
        /// </summary>
        public async Task<IEnumerable<DnsAnswer>> QueryDNS(string[] names, DnsRecordType recordType, string filter, bool includeAliasesInFilter, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (names == null || names.Length == 0) {
                throw new ArgumentNullException(nameof(names), $"No domain names provided for querying {recordType} records.");
            }
            if (QueryDnsOverride != null) {
                List<DnsAnswer> all = new();
                foreach (var n in names) {
                    all.AddRange(await QueryDnsOverride(n, recordType));
                }
                return all;
            }
            List<DnsAnswer> allAnswers = new();
            var filterOptions = includeAliasesInFilter ? new ResolveFilterOptions(true) : new ResolveFilterOptions();
            try {
                if (DnsEndpoints.Count > 0) {
                    foreach (var n in names) {
                        cancellationToken.ThrowIfCancellationRequested();
                        var arr = await ResolveWithEndpoints(n, recordType, filter, includeAliasesInFilter, DnsEndpoints.ToArray(), MultiResolverStrategy, MultiResolverMaxParallelism, cancellationToken).ConfigureAwait(false);
                        allAnswers.AddRange(arr);
                    }
                    return allAnswers;
                }

                using var client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
                client.EndpointConfiguration.UserAgent = UserAgent;
                if (ResolverMaxConcurrency.HasValue) {
                    client.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
                }
                DnsResponse[] data = (filter != string.Empty || includeAliasesInFilter)
                    ? await client.ResolveFilter(names, recordType, filter, filterOptions)
                    : await client.Resolve(names, recordType);

                foreach (var response in data) {
                    allAnswers.AddRange(response.Answers);
                }

                return allAnswers;
            } catch (Exception ex) when (ex is TaskCanceledException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException) {
                var fallbacks = GetFallbackEndpoints(DnsEndpoint);
                foreach (var fb in fallbacks) {
                    cancellationToken.ThrowIfCancellationRequested();
                    try {
                        using var clientFb = new ClientX(endpoint: fb, DnsSelectionStrategy);
                        clientFb.EndpointConfiguration.UserAgent = UserAgent;
                        if (ResolverMaxConcurrency.HasValue) {
                            clientFb.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
                        }
                        DnsResponse[] dataFb = (filter != string.Empty || includeAliasesInFilter)
                            ? await clientFb.ResolveFilter(names, recordType, filter, filterOptions)
                            : await clientFb.Resolve(names, recordType);
                        foreach (var response in dataFb) {
                            allAnswers.AddRange(response.Answers);
                        }
                        return allAnswers;
                    } catch (Exception retryEx) when (retryEx is TaskCanceledException || retryEx is TimeoutException || retryEx is System.Net.Http.HttpRequestException) {
                        // try next fallback
                    }
                }
                return allAnswers; // empty on failure
            }
        }

        private static DnsEndpoint[] GetFallbackEndpoints(DnsEndpoint current) {
            // Prefer system TCP as a robust baseline, then system resolver.
            // If already on system endpoints, try CloudflareWireFormat as a last resort.
            return current switch {
                DnsEndpoint.CloudflareWireFormat => new[] { DnsEndpoint.SystemTcp, DnsEndpoint.System },
                DnsEndpoint.SystemTcp => new[] { DnsEndpoint.System, DnsEndpoint.CloudflareWireFormat },
                DnsEndpoint.System => new[] { DnsEndpoint.SystemTcp, DnsEndpoint.CloudflareWireFormat },
                _ => new[] { DnsEndpoint.SystemTcp, DnsEndpoint.System }
            };
        }

        private static bool IsAnswerUseful(DnsResponse response) {
            try {
                if (response == null) return false;
                if (response.Status != DnsResponseCode.NoError) return false;
                return response.Answers != null && response.Answers.Length > 0;
            } catch { return false; }
        }

        private async Task<DnsAnswer[]> ResolveWithEndpoints(string name, DnsRecordType recordType, string filter, bool includeAliasesInFilter, DnsEndpoint[] endpoints, MultiResolverStrategy strategy, int? maxParallelism, CancellationToken ct)
        {
            if (endpoints == null || endpoints.Length == 0) return Array.Empty<DnsAnswer>();

            if (strategy == MultiResolverStrategy.SequentialAll) {
                foreach (var ep in endpoints) {
                    ct.ThrowIfCancellationRequested();
                    try {
                        using var c = new ClientX(endpoint: ep, DnsSelectionStrategy);
                        c.EndpointConfiguration.UserAgent = UserAgent;
                        if (ResolverMaxConcurrency.HasValue) c.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
                        var filterOptions = includeAliasesInFilter ? new ResolveFilterOptions(true) : new ResolveFilterOptions();
                        var resp = filter != string.Empty || includeAliasesInFilter
                            ? await c.ResolveFilter(name, recordType, filter, filterOptions).ConfigureAwait(false)
                            : await c.Resolve(name, recordType).ConfigureAwait(false);
                        if (IsAnswerUseful(resp)) return resp.Answers;
                    } catch { }
                }
                return Array.Empty<DnsAnswer>();
            }

            // Parallel
            var tasks = new List<Task<DnsResponse?>>();
            foreach (var ep in endpoints) {
                tasks.Add(Task.Run(async () => {
                    try {
                        using var c = new ClientX(endpoint: ep, DnsSelectionStrategy);
                        c.EndpointConfiguration.UserAgent = UserAgent;
                        if (ResolverMaxConcurrency.HasValue) c.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
                        var filterOptions = includeAliasesInFilter ? new ResolveFilterOptions(true) : new ResolveFilterOptions();
                        return filter != string.Empty || includeAliasesInFilter
                            ? await c.ResolveFilter(name, recordType, filter, filterOptions).ConfigureAwait(false)
                            : await c.Resolve(name, recordType).ConfigureAwait(false);
                    } catch { return null; }
                }, ct));
            }

            if (strategy == MultiResolverStrategy.FastestWins) {
                while (tasks.Count > 0) {
                    var finished = await Task.WhenAny(tasks).ConfigureAwait(false);
                    tasks.Remove(finished);
                    var resp = await finished.ConfigureAwait(false);
                    if (resp != null) return resp.Answers ?? Array.Empty<DnsAnswer>();
                }
                return Array.Empty<DnsAnswer>();
            }

            // FirstSuccess
            while (tasks.Count > 0) {
                var finished = await Task.WhenAny(tasks).ConfigureAwait(false);
                tasks.Remove(finished);
                var resp = await finished.ConfigureAwait(false);
                if (resp != null && IsAnswerUseful(resp)) return resp.Answers;
            }
            return Array.Empty<DnsAnswer>();
        }

        /// <summary>
        /// Queries the DNS for a list of names and a record type, optionally applying a filter, and returns the full DNS response.
        /// </summary>
        public async Task<IEnumerable<DnsResponse>> QueryFullDNS(string[] names, DnsRecordType recordType, string filter = "", CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (names == null || names.Length == 0) {
                throw new ArgumentNullException(nameof(names), $"No domain names provided for querying {recordType} records.");
            }
            if (DnsEndpoints.Count > 0) {
                var list = new List<DnsResponse>(names.Length);
                foreach (var n in names) {
                    var resp = await ResolveResponseWithEndpoints(n, recordType, filter, includeAliasesInFilter: false, DnsEndpoints.ToArray(), MultiResolverStrategy, MultiResolverMaxParallelism, cancellationToken).ConfigureAwait(false);
                    if (resp != null) list.Add(resp);
                }
                return list;
            }

            using var client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
            client.EndpointConfiguration.UserAgent = UserAgent;
            if (ResolverMaxConcurrency.HasValue) {
                client.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
            }
            DnsResponse[] data = filter != string.Empty
                ? await client.ResolveFilter(names, recordType, filter)
                : await client.Resolve(names, recordType);

            return data;
        }

        // No concurrency hint is applied in this build.
        private async Task<DnsResponse?> ResolveResponseWithEndpoints(string name, DnsRecordType recordType, string filter, bool includeAliasesInFilter, DnsEndpoint[] endpoints, MultiResolverStrategy strategy, int? maxParallelism, CancellationToken ct)
        {
            if (endpoints == null || endpoints.Length == 0) return null;
            if (strategy == MultiResolverStrategy.SequentialAll) {
                foreach (var ep in endpoints) {
                    ct.ThrowIfCancellationRequested();
                    try {
                        using var c = new ClientX(endpoint: ep, DnsSelectionStrategy);
                        c.EndpointConfiguration.UserAgent = UserAgent;
                        if (ResolverMaxConcurrency.HasValue) c.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
                        var filterOptions = includeAliasesInFilter ? new ResolveFilterOptions(true) : new ResolveFilterOptions();
                        var resp = filter != string.Empty || includeAliasesInFilter
                            ? await c.ResolveFilter(name, recordType, filter, filterOptions).ConfigureAwait(false)
                            : await c.Resolve(name, recordType).ConfigureAwait(false);
                        if (IsAnswerUseful(resp)) return resp;
                    } catch { }
                }
                return null;
            }

            var tasks = new List<Task<DnsResponse?>>();
            foreach (var ep in endpoints) {
                tasks.Add(Task.Run(async () => {
                    try {
                        using var c = new ClientX(endpoint: ep, DnsSelectionStrategy);
                        c.EndpointConfiguration.UserAgent = UserAgent;
                        if (ResolverMaxConcurrency.HasValue) c.EndpointConfiguration.MaxConcurrency = ResolverMaxConcurrency.Value;
                        var filterOptions = includeAliasesInFilter ? new ResolveFilterOptions(true) : new ResolveFilterOptions();
                        return filter != string.Empty || includeAliasesInFilter
                            ? await c.ResolveFilter(name, recordType, filter, filterOptions).ConfigureAwait(false)
                            : await c.Resolve(name, recordType).ConfigureAwait(false);
                    } catch { return null; }
                }, ct));
            }

            if (strategy == MultiResolverStrategy.FastestWins) {
                while (tasks.Count > 0) {
                    var finished = await Task.WhenAny(tasks).ConfigureAwait(false);
                    tasks.Remove(finished);
                    var resp = await finished.ConfigureAwait(false);
                    if (resp != null) return resp;
                }
                return null;
            }

            while (tasks.Count > 0) {
                var finished = await Task.WhenAny(tasks).ConfigureAwait(false);
                tasks.Remove(finished);
                var resp = await finished.ConfigureAwait(false);
                if (resp != null && IsAnswerUseful(resp)) return resp;
            }
            return null;
        }
    }

    /// <summary>Strategy used for multi-resolver DNS queries.</summary>
    public enum MultiResolverStrategy {
        FirstSuccess = 0,
        FastestWins = 1,
        SequentialAll = 2
    }
}
