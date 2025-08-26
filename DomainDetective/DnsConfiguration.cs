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
        /// Not applied unless <see cref="SupportsResolverConcurrency"/> is true in this build.
        /// </summary>
        public int? ResolverMaxConcurrency { get; set; }
        /// <summary>
        /// Indicates whether the underlying resolver supports a concurrency hint.
        /// If false, callers should not set <see cref="ResolverMaxConcurrency"/>.
        /// </summary>
        public bool SupportsResolverConcurrency => false;
        /// <summary>Optional override for DNS queries.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { get; set; }
        /// <summary>
        /// Gets or sets the DNS endpoint.
        /// </summary>
        public DnsEndpoint DnsEndpoint { get; set; }

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
        public async Task<DnsAnswer[]> QueryDNS(string name, DnsRecordType recordType, string filter = "", CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentNullException(nameof(name), $"Domain name cannot be null or empty when querying {recordType} records.");
            }
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, recordType);
            }
            using var client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
            client.EndpointConfiguration.UserAgent = UserAgent;
                        if (filter != string.Empty) {
                var data = await client.ResolveFilter(name, recordType, filter);
                return data.Answers;
            }

            var result = await client.Resolve(name, recordType);
            return result.Answers;
        }

        /// <summary>
        /// Queries the DNS for a list of names and a record type, optionally applying a filter.
        /// </summary>
        public async Task<IEnumerable<DnsAnswer>> QueryDNS(string[] names, DnsRecordType recordType, string filter = "", CancellationToken cancellationToken = default) {
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

            using var client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
            client.EndpointConfiguration.UserAgent = UserAgent;
                        DnsResponse[] data;
            if (filter != string.Empty) {
                data = await client.ResolveFilter(names, recordType, filter);
            } else {
                data = await client.Resolve(names, recordType);
            }

            foreach (var response in data) {
                allAnswers.AddRange(response.Answers);
            }

            return allAnswers;
        }

        /// <summary>
        /// Queries the DNS for a list of names and a record type, optionally applying a filter, and returns the full DNS response.
        /// </summary>
        public async Task<IEnumerable<DnsResponse>> QueryFullDNS(string[] names, DnsRecordType recordType, string filter = "", CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (names == null || names.Length == 0) {
                throw new ArgumentNullException(nameof(names), $"No domain names provided for querying {recordType} records.");
            }
            using var client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
            client.EndpointConfiguration.UserAgent = UserAgent;
                        DnsResponse[] data = filter != string.Empty
                ? await client.ResolveFilter(names, recordType, filter)
                : await client.Resolve(names, recordType);

            return data;
        }

        // No concurrency hint is applied in this build.
    }
}
