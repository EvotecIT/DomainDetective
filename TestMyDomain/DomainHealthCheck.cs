using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using DnsClient;
using DnsOverHttps;
using TestMyDomain.Protocols;

namespace TestMyDomain {
    public enum HealthCheckType {
        DMARC,
        SPF,
        DKIM,
        MX,
        CAA
    }

    public class DomainHealthCheck : Settings {
        /// <summary>
        /// Gets the dmarc analysis.
        /// </summary>
        /// <value>
        /// The dmarc analysis.
        /// </value>
        public DmarcAnalysis DmarcAnalysis { get; private set; } = new DmarcAnalysis();

        /// <summary>
        /// Gets the SPF analysis.
        /// </summary>
        /// <value>
        /// The SPF analysis.
        /// </value>
        public SpfAnalysis SpfAnalysis { get; private set; } = new SpfAnalysis();

        public DkimAnalysis DKIMAnalysis { get; private set; } = new DkimAnalysis();

        public MXAnalysis MXAnalysis { get; private set; } = new MXAnalysis();

        public CAAAnalysis CAAAnalysis { get; private set; } = new CAAAnalysis();

        public List<Answer> Answers;

        public async Task VerifyDKIM(string domainName, string[] selectors) {
            foreach (var selector in selectors) {
                var dkim = await QueryDNS($"{selector}._domainkey.{domainName}", "TXT", "DOH", "DKIM1");
                await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, _logger);
            }
        }

        public async Task Verify(string domainName, HealthCheckType[] healthCheckTypes = null, string[] dkimSelectors = null) {
            if (healthCheckTypes == null || healthCheckTypes.Length == 0) {
                healthCheckTypes = new[]                {
                    HealthCheckType.DMARC,
                    HealthCheckType.SPF,
                    HealthCheckType.DKIM,
                    HealthCheckType.MX,
                    HealthCheckType.CAA
                };
            }

            foreach (var healthCheckType in healthCheckTypes) {
                switch (healthCheckType) {
                    case HealthCheckType.DMARC:
                        var dmarc = await QueryDNS("_dmarc." + domainName, "TXT", "DOH", "DMARC1");
                        await DmarcAnalysis.AnalyzeDmarcRecords(dmarc, _logger);
                        break;
                    case HealthCheckType.SPF:
                        var spf = await QueryDNS(domainName, "TXT", "DOH", "SPF1");
                        //var spf = await QueryDNS(domainName, "TXT", "DNS", "SPF1");
                        await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
                        break;
                    case HealthCheckType.DKIM:
                        if (dkimSelectors != null) {
                            foreach (var selector in dkimSelectors) {
                                var dkim = await QueryDNS($"{selector}._domainkey.{domainName}", "TXT", "DOH", "DKIM1");
                                await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, _logger);
                            }
                        }
                        break;
                    case HealthCheckType.MX:
                        var mx = await QueryDNS(domainName, "MX", "DOH", "");
                        await MXAnalysis.AnalyzeMxRecords(mx, _logger);
                        break;
                    case HealthCheckType.CAA:
                        var caa = await QueryDNS(domainName, "CAA", "DOH", "");
                        await CAAAnalysis.AnalyzeCAARecords(caa, _logger);
                        break;
                }
            }
        }

        public async Task CheckDMARC(string dmarcRecord) {
            await DmarcAnalysis.AnalyzeDmarcRecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {dmarcRecord},
                    DataJoined = dmarcRecord
                }
            }, _logger);
        }

        public async Task CheckSPF(string spfRecord) {
            await SpfAnalysis.AnalyzeSpfRecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {spfRecord},
                    DataJoined = spfRecord
                }
            }, _logger);
        }

        public async Task CheckDKIM(string dkimRecord, string selector = "default") {
            await DKIMAnalysis.AnalyzeDkimRecords(selector, new List<DnsResult> {
                new DnsResult {
                    Data = new[] {dkimRecord},
                    DataJoined = dkimRecord
                }
            }, _logger);
        }

        public async Task CheckMX(string mxRecord) {
            await MXAnalysis.AnalyzeMxRecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {mxRecord},
                    DataJoined = mxRecord
                }
            }, _logger);
        }

        public async Task CheckCAA(string caaRecord) {
            await CAAAnalysis.AnalyzeCAARecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {caaRecord},
                    DataJoined = caaRecord
                }
            }, _logger);
        }

        internal static async Task<IEnumerable<DnsResult>> QueryDNS(string domainName, string dnsType, string provider, string filter, DnsEndpoint? dohEndpoint = null, string serverName = "") {
            if (provider == "DOH") {
                var queryResponseDOH = await QueryDOH(domainName, (ResourceRecordType)Enum.Parse(typeof(ResourceRecordType), dnsType));
                return DnsResult.TranslateFromDohResponse(queryResponseDOH, dnsType, filter);
            } else if (provider == "DNS") {
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

        private static async Task<Response> QueryDOH(string domainName, ResourceRecordType queryType, DnsEndpoint? dohEndpoint = DnsEndpoint.Cloudflare) {
            dohEndpoint ??= DnsEndpoint.Cloudflare;
            _logger.WriteVerbose($"Querying for {domainName} of type {queryType} using {dohEndpoint.Value}");
            var client = new DnsOverHttpsClient(dohEndpoint.Value);
            var response = await client.Resolve(domainName, queryType);
            return response;
        }
    }
}
