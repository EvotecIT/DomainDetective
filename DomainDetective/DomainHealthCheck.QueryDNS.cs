using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using DnsClient;
using DnsClientX;

namespace DomainDetective {
    public partial class DomainHealthCheck : Settings {

        internal static async Task<IEnumerable<DnsResult>> QueryDNS(string domainName, string dnsType, DnsProvider provider, string filter, DnsEndpoint? dohEndpoint = null, string serverName = "") {
            if (provider == DnsProvider.DnsOverHttps) {
                var queryResponseDOH = await QueryDOH(domainName, (DnsRecordType)Enum.Parse(typeof(DnsRecordType), dnsType));
                return DnsResult.TranslateFromDohResponse(queryResponseDOH, dnsType, filter);
            } else if (provider == DnsProvider.Standard) {
                var queryResponse = await QueryDNSServer(domainName, (QueryType)Enum.Parse(typeof(QueryType), dnsType));
                return DnsResult.TranslateFromDnsQueryResponse(queryResponse, dnsType, filter);
            } else {
                throw new Exception("Invalid provider");
            }
        }

        private static async Task<IDnsQueryResponse> QueryDNSServer(string domainName, QueryType queryType, string serverName = "") {
            LookupClientOptions options;
            if (serverName == "") {
                _logger.WriteVerbose($"Querying for {domainName} of type {queryType}");
                options = new LookupClientOptions();
            } else {
                _logger.WriteVerbose($"Querying for {domainName} of type {queryType} using {serverName}");
                var endpoint = new IPEndPoint(IPAddress.Parse(serverName), 0);
                options = new LookupClientOptions(endpoint);
            }
            options.Timeout = TimeSpan.FromSeconds(2);
            var lookup = new LookupClient(options);

            try {
                var result = await lookup.QueryAsync(domainName, queryType);
                return result;
            } catch (DnsResponseException ex) {
                _logger.WriteWarning($"DNS query for {domainName} of type {queryType} failed: {ex.Message}");
                return null; // or handle the exception in another appropriate way
            }
        }

        private static async Task<DnsResponse> QueryDOH(string domainName, DnsRecordType queryType, DnsEndpoint dohEndpoint = DnsEndpoint.Google) {
            _logger.WriteVerbose($"Querying for {domainName} of type {queryType} using {dohEndpoint}");
            var client = new DnsClientX.ClientX(dohEndpoint);
            var response = await client.Resolve(domainName, queryType);
            return response;
        }
    }
}
