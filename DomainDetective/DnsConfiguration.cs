using System.Collections.Generic;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective {
    /// <summary>
    /// Represents the configuration for DNS queries.
    /// </summary>
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
            DnsEndpoint = DnsEndpoint.Cloudflare;
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
        public async Task<DnsAnswer[]> QueryDNS(string name, DnsRecordType recordType, string filter = "") {
            ClientX client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
            if (filter != "") {
                var data = await client.ResolveFilter(name, recordType, filter);
                return data.Answers;
            } else {
                var data = await client.Resolve(name, recordType);
                return data.Answers;
            }
        }

        /// <summary>
        /// Queries the DNS for a list of names and a record type, optionally applying a filter.
        /// </summary>
        public async Task<IEnumerable<DnsAnswer>> QueryDNS(string[] names, DnsRecordType recordType, string filter = "") {
            List<DnsAnswer> allAnswers = new List<DnsAnswer>();

            ClientX client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
            DnsResponse[] data;
            if (filter != "") {
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
        public async Task<IEnumerable<DnsResponse>> QueryFullDNS(string[] names, DnsRecordType recordType, string filter = "") {
            List<DnsAnswer> allAnswers = new List<DnsAnswer>();

            ClientX client = new ClientX(endpoint: DnsEndpoint, DnsSelectionStrategy);
            DnsResponse[] data;
            if (filter != "") {
                data = await client.ResolveFilter(names, recordType, filter);
            } else {
                data = await client.Resolve(names, recordType);
            }

            return data;
        }
    }
}
