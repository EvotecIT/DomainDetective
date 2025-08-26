using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes apex A/AAAA records for a domain and surfaces whether
    /// address records exist that SMTP could use as a fallback when
    /// MX records are absent (RFC 5321).
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public sealed class ApexAddressAnalysis {
        /// <summary>DNS configuration used for lookups when needed.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Optional DNS query override for testing.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>Apex A records discovered.</summary>
        public List<string> ARecords { get; private set; } = new();
        /// <summary>Apex AAAA records discovered.</summary>
        public List<string> AaaaRecords { get; private set; } = new();
        /// <summary>True when at least one A record exists.</summary>
        public bool HasARecord { get; private set; }
        /// <summary>True when at least one AAAA record exists.</summary>
        public bool HasAaaaRecord { get; private set; }
        /// <summary>True when either A or AAAA records exist.</summary>
        public bool HasAnyAddress => HasARecord || HasAaaaRecord;

        /// <summary>Relevant standards for apex address (SMTP fallback) behavior.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "Simple Mail Transfer Protocol", Reference = "RFC 5321", Url = "https://datatracker.ietf.org/doc/html/rfc5321" },
            new StandardReference { Title = "Special-Purpose Address Registries", Reference = "RFC 6890", Url = "https://datatracker.ietf.org/doc/html/rfc6890" },
            new StandardReference { Title = "An Infrastructure to Support Secure Internet Routing", Reference = "RFC 6480", Url = "https://datatracker.ietf.org/doc/html/rfc6480" }
        };

        // Counts and diversity
        public int IPv4Count { get; private set; }
        public int IPv6Count { get; private set; }
        public int DistinctSubnetCountV4 { get; private set; }
        public int DistinctSubnetCountV6 { get; private set; }

        // Address quality/visibility
        public int PrivateAddressCount { get; private set; }
        public int LoopbackCount { get; private set; }
        public int LinkLocalCount { get; private set; }
        public int MulticastCount { get; private set; }
        public int DocumentationAddressCount { get; private set; }
        public int UniqueLocalV6Count { get; private set; }
        public int PublicAddressCount { get; private set; }

        // Reverse DNS details
        public Dictionary<string, List<string>> PtrByIp { get; private set; } = new();
        public bool AnyPtrPresent { get; private set; }
        public bool AllPtrPresent { get; private set; }
        public int FcrDnsValidCount { get; private set; }
        public bool AllFcrDnsValid { get; private set; }

        // ASN + RPKI
        public Dictionary<string, int> AsnByIp { get; private set; } = new();
        public int AsnDistinctCount { get; private set; }
        public int RpkiValidCount { get; private set; }
        public bool AllRpkiValid { get; private set; }

        /// <summary>Optional override for RPKI lookups when testing.</summary>
        public Func<string, Task<(string Prefix, int Asn, bool Valid)>>? QueryRpkiOverride { private get; set; }

        public void Reset() {
            ARecords = new List<string>();
            AaaaRecords = new List<string>();
            HasARecord = false;
            HasAaaaRecord = false;
            IPv4Count = 0;
            IPv6Count = 0;
            DistinctSubnetCountV4 = 0;
            DistinctSubnetCountV6 = 0;
            PrivateAddressCount = 0;
            LoopbackCount = 0;
            LinkLocalCount = 0;
            MulticastCount = 0;
            DocumentationAddressCount = 0;
            UniqueLocalV6Count = 0;
            PublicAddressCount = 0;
            PtrByIp = new();
            AnyPtrPresent = false;
            AllPtrPresent = false;
            FcrDnsValidCount = 0;
            AllFcrDnsValid = false;
            AsnByIp = new();
            AsnDistinctCount = 0;
            RpkiValidCount = 0;
            AllRpkiValid = false;
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }
            return await DnsConfiguration.QueryDNS(name, type);
        }

        /// <summary>
        /// Analyzes apex address answers supplied by the caller.
        /// </summary>
        public Task AnalyzeApexAnswers(IEnumerable<DnsAnswer> aAnswers, IEnumerable<DnsAnswer> aaaaAnswers, InternalLogger? logger = null) {
            Reset();
            if (aAnswers != null) {
                foreach (var a in aAnswers) {
                    if (!string.IsNullOrWhiteSpace(a.Data)) {
                        ARecords.Add(a.Data);
                    }
                }
            }
            if (aaaaAnswers != null) {
                foreach (var a in aaaaAnswers) {
                    if (!string.IsNullOrWhiteSpace(a.Data)) {
                        AaaaRecords.Add(a.Data);
                    }
                }
            }

            HasARecord = ARecords.Count > 0;
            HasAaaaRecord = AaaaRecords.Count > 0;

            // Compute counts and diversity
            IPv4Count = ARecords.Count;
            IPv6Count = AaaaRecords.Count;
            DistinctSubnetCountV4 = DistinctSubnets(ARecords);
            DistinctSubnetCountV6 = DistinctSubnets(AaaaRecords);

            // Visibility categories
            foreach (var rec in ARecords.Concat(AaaaRecords)) {
                if (System.Net.IPAddress.TryParse(rec, out var ip)) {
                    var (isPublic, isPrivate, isLoop, isLinkLocal, isMulticast, isDoc, isUla) = ClassifyAddress(ip);
                    if (isPrivate) PrivateAddressCount++;
                    if (isLoop) LoopbackCount++;
                    if (isLinkLocal) LinkLocalCount++;
                    if (isMulticast) MulticastCount++;
                    if (isDoc) DocumentationAddressCount++;
                    if (isUla) UniqueLocalV6Count++;
                    if (isPublic) PublicAddressCount++;
                }
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Queries and analyzes apex A/AAAA for the given domain using configured DNS.
        /// </summary>
        public async Task AnalyzeAsync(string domainName, InternalLogger? logger = null) {
            Reset();
            var a = await QueryDns(domainName, DnsRecordType.A) ?? Array.Empty<DnsAnswer>();
            var aaaa = await QueryDns(domainName, DnsRecordType.AAAA) ?? Array.Empty<DnsAnswer>();
            await AnalyzeApexAnswers(a, aaaa, logger);
            await AnalyzeReverseDnsAsync(domainName, logger);
            await AnalyzeAsnAndRpkiAsync(domainName, logger);
        }

        /// <summary>
        /// Performs PTR and FCrDNS checks for apex addresses.
        /// </summary>
        public async Task AnalyzeReverseDnsAsync(string domainName, InternalLogger? logger = null) {
            var r = new ReverseDnsAnalysis { DnsConfiguration = this.DnsConfiguration };
            if (this.QueryDnsOverride != null) {
                r.QueryDnsOverride = this.QueryDnsOverride;
            }
            await r.AnalyzeHosts(new[] { domainName }, logger);
            PtrByIp = new();
            AnyPtrPresent = false;
            AllPtrPresent = true;
            FcrDnsValidCount = 0;
            foreach (var res in r.Results) {
                if (!PtrByIp.TryGetValue(res.IpAddress, out var list)) {
                    list = new List<string>();
                    PtrByIp[res.IpAddress] = list;
                }
                list.AddRange(res.PtrRecords);
                AnyPtrPresent = AnyPtrPresent || res.PtrRecords.Count > 0;
                AllPtrPresent = AllPtrPresent && res.PtrRecords.Count > 0;
                if (res.FcrDnsValid) {
                    FcrDnsValidCount++;
                }
            }
            AllFcrDnsValid = (PtrByIp.Count > 0) && (FcrDnsValidCount == PtrByIp.Count);
        }

        private static int DistinctSubnets(IEnumerable<string> records) {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var rec in records) {
                if (System.Net.IPAddress.TryParse(rec, out var ip)) {
                    set.Add(ip.GetSubnetKey());
                }
            }
            return set.Count;
        }

        private static (bool Public, bool Private, bool Loopback, bool LinkLocal, bool Multicast, bool Documentation, bool UniqueLocalV6) ClassifyAddress(System.Net.IPAddress ip) {
            bool isPrivate = false, isLoop = false, isLinkLocal = false, isMulticast = false, isDoc = false, isUla = false;
            if (System.Net.IPAddress.IsLoopback(ip)) isLoop = true;
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) {
                var b = ip.GetAddressBytes();
                // Private
                if (b[0] == 10 || (b[0] == 172 && (b[1] >= 16 && b[1] <= 31)) || (b[0] == 192 && b[1] == 168)) isPrivate = true;
                // Link-local 169.254/16
                if (b[0] == 169 && b[1] == 254) isLinkLocal = true;
                // Multicast 224/4
                if (b[0] >= 224 && b[0] <= 239) isMulticast = true;
                // Documentation blocks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
                if ((b[0] == 192 && b[1] == 0 && b[2] == 2) || (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113)) isDoc = true;
            } else {
                // IPv6
                if (ip.IsIPv6LinkLocal) isLinkLocal = true;
                if (ip.IsIPv6Multicast) isMulticast = true;
                // Unique local fc00::/7
                var bytes = ip.GetAddressBytes();
                if ((bytes[0] & 0xFE) == 0xFC) isUla = true;
            }
            bool isPublic = !(isPrivate || isLoop || isLinkLocal || isMulticast || isDoc || isUla);
            return (isPublic, isPrivate, isLoop, isLinkLocal, isMulticast, isDoc, isUla);
        }

        /// <summary>
        /// Populates ASN and RPKI validity for apex addresses using RPKIAnalysis.
        /// </summary>
        public async Task AnalyzeAsnAndRpkiAsync(string domainName, InternalLogger? logger = null) {
            var rpki = new RPKIAnalysis { DnsConfiguration = this.DnsConfiguration };
            if (this.QueryDnsOverride != null) rpki.QueryDnsOverride = this.QueryDnsOverride;
            if (this.QueryRpkiOverride != null) rpki.QueryRpkiOverride = this.QueryRpkiOverride;
            await rpki.Analyze(domainName, logger);

            AsnByIp = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            RpkiValidCount = 0;
            foreach (var r in rpki.Results) {
                // only map apex IPs we actually have
                if (ARecords.Contains(r.IpAddress, StringComparer.OrdinalIgnoreCase) || AaaaRecords.Contains(r.IpAddress, StringComparer.OrdinalIgnoreCase)) {
                    AsnByIp[r.IpAddress] = r.Asn;
                    if (r.Valid) RpkiValidCount++;
                }
            }
            AsnDistinctCount = AsnByIp.Values.Distinct().Count();
            AllRpkiValid = (AsnByIp.Count > 0) && (RpkiValidCount == AsnByIp.Count);
        }
    }
}
