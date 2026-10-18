using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;

namespace DomainDetective {
    /// <summary>
    /// Analyzes apex A/AAAA records for a domain and surfaces whether
    /// address records exist that SMTP could use as a fallback when
    /// MX records are absent (RFC 5321).
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
public sealed class ApexAddressAnalysis {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>DNS configuration used for lookups when needed.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Optional DNS query override for testing.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>Apex A records discovered.</summary>
        public List<string> ARecords { get; private set; } = new();
        /// <summary>Apex AAAA records discovered.</summary>
        public List<string> AaaaRecords { get; private set; } = new();
        /// <summary>True when at least one A record exists.</summary>
        public bool HasARecord => ARecords != null && ARecords.Count > 0;
        /// <summary>True when at least one AAAA record exists.</summary>
        public bool HasAaaaRecord => AaaaRecords != null && AaaaRecords.Count > 0;
        /// <summary>True when either A or AAAA records exist.</summary>
        public bool HasAnyAddress => (ARecords != null && ARecords.Count > 0) || (AaaaRecords != null && AaaaRecords.Count > 0) || HasARecord || HasAaaaRecord;

        /// <summary>Whether both address-family lookups completed conclusively.</summary>
        public bool AddressLookupComplete => ALookupComplete && AaaaLookupComplete;
        /// <summary>Whether the IPv4 lookup returned a conclusive answer or negative response.</summary>
        public bool ALookupComplete { get; private set; }
        /// <summary>Whether the IPv6 lookup returned a conclusive answer or negative response.</summary>
        public bool AaaaLookupComplete { get; private set; }
        /// <summary>True for a confirmed address, false for confirmed absence, or null when absence is unestablished.</summary>
        public bool? AddressPresence => HasAnyAddress ? true : AddressLookupComplete ? false : null;
        /// <summary>Operational failures that prevented complete address discovery.</summary>
        public IReadOnlyList<string> AddressLookupFailures { get; private set; } = Array.Empty<string>();

        /// <summary>Relevant standards for apex address (SMTP fallback) behavior.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "Simple Mail Transfer Protocol", Reference = "RFC 5321", Url = "https://datatracker.ietf.org/doc/html/rfc5321" },
            new StandardReference { Title = "Special-Purpose Address Registries", Reference = "RFC 6890", Url = "https://datatracker.ietf.org/doc/html/rfc6890" },
            new StandardReference { Title = "An Infrastructure to Support Secure Internet Routing", Reference = "RFC 6480", Url = "https://datatracker.ietf.org/doc/html/rfc6480" }
        };

        // Counts and diversity
        /// <summary>Gets or sets the i pv4 count value.</summary>
        public int IPv4Count { get; private set; }
        /// <summary>Gets or sets the i pv6 count value.</summary>
        public int IPv6Count { get; private set; }
        /// <summary>Gets or sets the distinct subnet count v4 value.</summary>
        public int DistinctSubnetCountV4 { get; private set; }
        /// <summary>Gets or sets the distinct subnet count v6 value.</summary>
        public int DistinctSubnetCountV6 { get; private set; }

        // Address quality/visibility
        /// <summary>Gets or sets the private address count value.</summary>
        public int PrivateAddressCount { get; private set; }
        /// <summary>Gets or sets the loopback count value.</summary>
        public int LoopbackCount { get; private set; }
        /// <summary>Gets or sets the link local count value.</summary>
        public int LinkLocalCount { get; private set; }
        /// <summary>Gets or sets the multicast count value.</summary>
        public int MulticastCount { get; private set; }
        /// <summary>Gets or sets the documentation address count value.</summary>
        public int DocumentationAddressCount { get; private set; }
        /// <summary>Gets or sets the unique local v6 count value.</summary>
        public int UniqueLocalV6Count { get; private set; }
        /// <summary>Gets or sets the public address count value.</summary>
        public int PublicAddressCount { get; private set; }

        // Reverse DNS details
        /// <summary>Gets or sets the ptr by ip value.</summary>
        public Dictionary<string, List<string>> PtrByIp { get; private set; } = new();
        /// <summary>Gets or sets the any ptr present value.</summary>
        public bool AnyPtrPresent { get; private set; }
        /// <summary>Gets or sets the all ptr present value.</summary>
        public bool AllPtrPresent { get; private set; }
        /// <summary>Gets or sets the fcr dns valid count value.</summary>
        public int FcrDnsValidCount { get; private set; }
        /// <summary>Gets or sets the all fcr dns valid value.</summary>
        public bool AllFcrDnsValid { get; private set; }

        // ASN + RPKI
        /// <summary>Gets or sets the asn by ip value.</summary>
        public Dictionary<string, int> AsnByIp { get; private set; } = new();
        /// <summary>Gets or sets the asn distinct count value.</summary>
        public int AsnDistinctCount { get; private set; }
        /// <summary>Gets or sets the rpki valid count value.</summary>
        public int RpkiValidCount { get; private set; }
        /// <summary>Gets or sets the all rpki valid value.</summary>
        public bool AllRpkiValid { get; private set; }

        /// <summary>Optional override for RPKI lookups when testing.</summary>
        public Func<string, Task<(string Prefix, int Asn, bool Valid)>>? QueryRpkiOverride { private get; set; }

        /// <summary>Executes the reset operation.</summary>
        public void Reset() {
            ALookupComplete = AaaaLookupComplete = false;
            AddressLookupFailures = Array.Empty<string>();
            ARecords = new List<string>();
            AaaaRecords = new List<string>();
            // flags are computed from lists
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

        private static string NormalizeName(string name)
        {
            return (name ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken ct) {
            var q = NormalizeName(name);
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(q, type).WaitWithCancellation(ct);
            }
            return await DnsConfiguration.QueryPolicyDNS(q, type, cancellationToken: ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Analyzes apex address answers supplied by the caller.
        /// </summary>
        public Task AnalyzeApexAnswers(IEnumerable<DnsAnswer> aAnswers, IEnumerable<DnsAnswer> aaaaAnswers, InternalLogger? logger = null) {
            Reset();
            ALookupComplete = AaaaLookupComplete = true;
            if (aAnswers != null) {
                foreach (var a in aAnswers) {
                    var val = a.Data ?? a.DataRaw;
                    if (!string.IsNullOrWhiteSpace(val)) {
                        ARecords.Add(val);
                    }
                }
            }
            if (aaaaAnswers != null) {
                foreach (var a in aaaaAnswers) {
                    var val = a.Data ?? a.DataRaw;
                    if (!string.IsNullOrWhiteSpace(val)) {
                        AaaaRecords.Add(val);
                    }
                }
            }

            // flags are computed from lists; no assignments

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
            if (PublicAddressCount > 0) {
                logger?.WriteInformationCode(ApexAddressCodes.PubliclyRoutable, "Apex addresses are publicly routable");
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Queries and analyzes apex A/AAAA for the given domain using configured DNS.
        /// </summary>
        public Task AnalyzeAsync(string domainName, InternalLogger? logger = null) => AnalyzeAsync(domainName, logger, default);

        /// <summary>Analyzes apex addresses and all requested enrichment with caller cancellation.</summary>
        public async Task AnalyzeAsync(string domainName, InternalLogger? logger, CancellationToken cancellationToken) {
            Reset();
            Subject = domainName;
            async Task<(DnsAnswer[] Answers, string? Failure)> Lookup(DnsRecordType type) {
                try {
                    return (await QueryDns(domainName, type, cancellationToken).ConfigureAwait(false) ?? Array.Empty<DnsAnswer>(), null);
                } catch (Exception ex) when (!cancellationToken.IsCancellationRequested &&
                    (ex is DnsQueryFailureException || ex is System.Net.Http.HttpRequestException ||
                     ex is System.IO.IOException || ex is System.Net.Sockets.SocketException ||
                     ex is TimeoutException || ex is OperationCanceledException)) {
                    return (Array.Empty<DnsAnswer>(), $"{type}: {ex.Message}");
                }
            }
            var aTask = Lookup(DnsRecordType.A);
            var aaaaTask = Lookup(DnsRecordType.AAAA);
            await Task.WhenAll(aTask, aaaaTask).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var a = await aTask;
            var aaaa = await aaaaTask;
            await AnalyzeApexAnswers(a.Answers, aaaa.Answers, logger);
            AddressLookupFailures = new[] { a.Failure, aaaa.Failure }.Where(value => value != null).Select(value => value!).ToArray();
            ALookupComplete = a.Failure == null;
            AaaaLookupComplete = aaaa.Failure == null;
            if (!AddressLookupComplete) {
                logger?.WriteInformationCode("APEXADDRESS.Lookup.Incomplete", "Apex address evidence is incomplete; absence was not established for every address family.");
            }
            if (!HasAnyAddress) { return; }
            await Task.WhenAll(AnalyzeReverseDnsAsync(domainName, logger, cancellationToken),
                AnalyzeAsnAndRpkiAsync(domainName, logger, cancellationToken)).ConfigureAwait(false);
        }

        /// <summary>
        /// Performs PTR and FCrDNS checks for apex addresses.
        /// </summary>
        public Task AnalyzeReverseDnsAsync(string domainName, InternalLogger? logger = null) => AnalyzeReverseDnsAsync(domainName, logger, default);

        private async Task AnalyzeReverseDnsAsync(string domainName, InternalLogger? logger, CancellationToken cancellationToken) {
            var r = new ReverseDnsAnalysis { DnsConfiguration = this.DnsConfiguration };
            if (this.QueryDnsOverride != null) {
                r.QueryDnsOverride = this.QueryDnsOverride;
            }
            await r.AnalyzeHosts(new[] { domainName }, logger, cancellationToken);
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
            if (AllFcrDnsValid) {
                logger?.WriteInformationCode(ApexAddressCodes.FcrDnsValid, "Apex addresses have forward-confirmed reverse DNS");
            }
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
        public Task AnalyzeAsnAndRpkiAsync(string domainName, InternalLogger? logger = null) => AnalyzeAsnAndRpkiAsync(domainName, logger, default);

        private async Task AnalyzeAsnAndRpkiAsync(string domainName, InternalLogger? logger, CancellationToken cancellationToken) {
            var rpki = new RPKIAnalysis { DnsConfiguration = this.DnsConfiguration };
            if (this.QueryDnsOverride != null) rpki.QueryDnsOverride = this.QueryDnsOverride;
            if (this.QueryRpkiOverride != null) rpki.QueryRpkiOverride = this.QueryRpkiOverride;
            await rpki.Analyze(domainName, logger, cancellationToken);

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
