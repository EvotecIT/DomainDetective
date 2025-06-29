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
    public class DnsConfiguration {
        /// <summary>
        /// Gets or sets the DNS endpoint.
        /// </summary>
        public DnsEndpoint DnsEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the DNS selection strategy.
        /// </summary>
        public DnsSelectionStrategy DnsSelectionStrategy { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DnsConfiguration"/> class with default values.
        /// </summary>
        public DnsConfiguration() {
            DnsEndpoint = DnsEndpoint.CloudflareWireFormat;
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
            ClientX client = new(endpoint: DnsEndpoint, DnsSelectionStrategy);
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
            List<DnsAnswer> allAnswers = new();

            ClientX client = new(endpoint: DnsEndpoint, DnsSelectionStrategy);
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
            ClientX client = new(endpoint: DnsEndpoint, DnsSelectionStrategy);
            DnsResponse[] data = filter != string.Empty
                ? await client.ResolveFilter(names, recordType, filter)
                : await client.Resolve(names, recordType);

            return data;
        }
    }
}