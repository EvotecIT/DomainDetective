using DnsClientX;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective {
    public class DNSBLRecord {
        /// <summary>Gets or sets the queried IP address in reverse format.</summary>
        public string IPAddress { get; set; }
        /// <summary>Gets or sets the original IP address or hostname.</summary>
        public string OriginalIPAddress { get; set; }
        /// <summary>Gets or sets the fully qualified domain name that was queried.</summary>
        public string FQDN { get; set; }
        /// <summary>Gets or sets the blacklist domain.</summary>
        public string BlackList { get; set; }
        //public string BlackListReason { get; set; }
        /// <summary>Gets or sets a value indicating whether the address was listed.</summary>
        public bool IsBlackListed { get; set; }
        /// <summary>Gets or sets the raw DNSBL response.</summary>
        public string Answer { get; set; }
        /// <summary>Gets or sets the interpreted meaning of <see cref="Answer"/>.</summary>
        public string ReplyMeaning { get; set; }
        //public string NameServer { get; set; }
    }

    public class DNSQueryResult {
        /// <summary>Gets or sets the host that was checked.</summary>
        public string Host { get; set; }
        /// <summary>Gets or sets the DNSBL results.</summary>
        public IEnumerable<DNSBLRecord> DNSBLRecords { get; set; }
        /// <summary>Gets the number of blacklists that reported a listing.</summary>
        public int Listed => DNSBLRecords.Count(record => record.IsBlackListed);

        /// <summary>Gets the names of blacklists that reported a listing.</summary>
        public List<string> ListedBlacklist => DNSBLRecords.Where(record => record.IsBlackListed).Select(record => record.BlackList).ToList();

        /// <summary>Gets the number of lists where the host was not found.</summary>
        public int NotListed => DNSBLRecords.Count(record => !record.IsBlackListed);
        /// <summary>Gets the total number of DNSBL checks performed.</summary>
        public int Total => DNSBLRecords.Count();
        /// <summary>Gets a value indicating whether the host was listed on any blacklist.</summary>
        public bool IsBlacklisted => Listed > 0;
    }

    public class DnsblEntry {
        /// <summary>Gets or sets the blacklist domain.</summary>
        public string Domain { get; set; }
        /// <summary>Gets or sets a value indicating whether the entry is used during checks.</summary>
        public bool Enabled { get; set; } = true;
        /// <summary>Gets or sets optional descriptive text.</summary>
        public string Comment { get; set; }

        public DnsblEntry() { }
        public DnsblEntry(string domain, bool enabled = true, string comment = null) {
            Domain = domain;
            Enabled = enabled;
            Comment = comment;
        }
    }

    public class DNSBLAnalysis {
        internal DnsConfiguration DnsConfiguration { get; set; }

        /// <summary>
        /// Gets the collection of configured DNSBL provider entries.
        /// Use <see cref="AddDNSBL(string, bool, string)"/>, <see cref="RemoveDNSBL(string)"/>,
        /// <see cref="ClearDNSBL()"/>, <see cref="LoadDNSBL(string, bool)"/> or
        /// <see cref="LoadDnsblConfig(string, bool, bool)"/> to modify the list.
        /// </summary>
        /// <value>
        /// The DNSBL provider entries.
        /// </value>
        internal List<DnsblEntry> DnsblEntries { get; } = new()
        {
            new("all.s5h.net"),
            new("auth.spamrats.com"),
            new("b.barracudacentral.org"),
            new("bad.virusfree.cz"),
            new("badconf.rhsbl.sorbs.net"),
            new("bip.virusfree.cz"),
            new("bl.0spam.org"),
            new("bl.blocklist.de"),
            new("bl.deadbeef.com"),
            new("bl.mailspike.org"),
            new("bl.nordspam.com"),
            new("bl.spamcop.net"),
            new("black.dnsbl.brukalai.lt"),
            new("black.mail.abusix.zone"),
            new("blackholes.five-ten-sg.com"),
            new("blacklist.woody.ch"),
            new("block.dnsbl.sorbs.net"),
            new("bogons.cymru.com"),
            new("cbl.abuseat.org"),
            new("combined.abuse.ch"),
            new("combined.mail.abusix.zone"),
            new("combined.rbl.msrbl.net"),
            new("db.wpbl.info"),
            new("dbl.0spam.org"),
            new("dbl.nordspam.com"),
            new("dbl.spamhaus.org"),
            new("dblack.mail.abusix.zone"),
            new("diskhash.mail.abusix.zone"),
            new("dnsbl.cyberlogic.net"),
            new("dnsbl.dronebl.org"),
            new("dnsbl.inps.de"),
            new("dnsbl.justspam.org"),
            new("dnsbl.sorbs.net", enabled: false, comment: "https://github.com/EvotecIT/PSBlackListChecker/issues/11"),
            new("dnsbl-1.uceprotect.net"),
            new("dnsbl-2.uceprotect.net"),
            new("dnsbl-3.uceprotect.net"),
            new("drone.abuse.ch"),
            new("duinv.aupads.org"),
            new("dul.dnsbl.sorbs.net"),
            new("dul.ru"),
            new("dyna.spamrats.com"),
            new("dynamic.mail.abusix.zone"),
            new("escalations.dnsbl.sorbs.net"),
            new("exploit.mail.abusix.zone"),
            new("hbl.spamhaus.org"),
            new("hostkarma.junkemailfilter.com"),
            new("http.dnsbl.sorbs.net", enabled: false, comment: "https://github.com/EvotecIT/PSBlackListChecker/issues/11"),
            new("images.rbl.msrbl.net"),
            new("ips.backscatterer.org"),
            new("ix.dnsbl.manitu.net"),
            new("key.authbl.dq.spamhaus.net"),
            new("korea.services.net"),
            new("misc.dnsbl.sorbs.net", enabled: false, comment: "https://github.com/EvotecIT/PSBlackListChecker/issues/11"),
            new("nbl.0spam.org"),
            new("new.spam.dnsbl.sorbs.net"),
            new("nod.mail.abusix.zone"),
            new("nomail.rhsbl.sorbs.net"),
            new("noptr.spamrats.com"),
            new("noservers.dnsbl.sorbs.net"),
            new("ohps.dnsbl.net.au"),
            new("old.spam.dnsbl.sorbs.net"),
            new("omrs.dnsbl.net.au"),
            new("orvedb.aupads.org"),
            new("osps.dnsbl.net.au"),
            new("osrs.dnsbl.net.au"),
            new("owfs.dnsbl.net.au"),
            new("owps.dnsbl.net.au"),
            new("pbl.spamhaus.org"),
            new("phishing.rbl.msrbl.net"),
            new("probes.dnsbl.net.au"),
            new("proxy.bl.gweep.ca"),
            new("proxy.block.transip.nl"),
            new("psbl.surriel.com"),
            new("rbl.0spam.org"),
            new("rbl.interserver.net"),
            new("rbl.metunet.com"),
            new("rdts.dnsbl.net.au"),
            new("recent.spam.dnsbl.sorbs.net"),
            new("relays.bl.gweep.ca"),
            new("relays.bl.kundenserver.de"),
            new("relays.nether.net"),
            new("residential.block.transip.nl"),
            new("rhsbl.sorbs.net"),
            new("ricn.dnsbl.net.au"),
            new("rmst.dnsbl.net.au"),
            new("safe.dnsbl.sorbs.net"),
            new("sbl.spamhaus.org"),
            new("short.rbl.jp"),
            new("shorthash.mail.abusix.zone"),
            new("singular.ttk.pte.hu"),
            new("smtp.dnsbl.sorbs.net", enabled: false, comment: "https://github.com/EvotecIT/PSBlackListChecker/issues/11"),
            new("socks.dnsbl.sorbs.net", enabled: false, comment: "https://github.com/EvotecIT/PSBlackListChecker/issues/11"),
            new("spam.abuse.ch"),
            new("spam.dnsbl.anonmails.de"),
            new("spam.dnsbl.sorbs.net", enabled: false, comment: "https://github.com/EvotecIT/PSBlackListChecker/issues/11"),
            new("spam.rbl.msrbl.net"),
            new("spam.spamrats.com"),
            new("spambot.bls.digibase.ca"),
            new("spamlist.or.kr"),
            new("spamrbl.imp.ch"),
            new("spamsources.fabel.dk"),
            new("t3direct.dnsbl.net.au"),
            new("ubl.lashback.com"),
            new("ubl.unsubscore.com"),
            new("virbl.bit.nl"),
            new("virus.rbl.jp"),
            new("virus.rbl.msrbl.net"),
            new("web.dnsbl.sorbs.net", enabled: false, comment: "https://github.com/EvotecIT/PSBlackListChecker/issues/11"),
            new("wormrbl.imp.ch"),
            new("xbl.spamhaus.org"),
            new("z.mailspike.net"),
            new("zen.spamhaus.org"),
            new("zombie.dnsbl.sorbs.net", enabled: false, comment: "https://github.com/EvotecIT/PSBlackListChecker/issues/11"),
            new("bl.emailbasura.org", enabled: false, comment: "dead as per https://github.com/EvotecIT/PSBlackListChecker/issues/8"),
            new("dynip.rothen.com", enabled: false, comment: "dead as per https://github.com/EvotecIT/PSBlackListChecker/issues/9"),
            new("bl.spamcannibal.org", enabled: false, comment: "now a parked domain"),
            new("tor.ahbl.org", enabled: false, comment: "terminated in 2015"),
            new("tor.dnsbl.sectoor.de", enabled: false, comment: "parked domain"),
            new("torserver.tor.dnsbl.sectoor.de", enabled: false, comment: "as above"),
            new("dnsbl.njabl.org", enabled: false, comment: "supposedly doesn't work properly anymore"),
            new("dnsbl.ahbl.org", enabled: false, comment: "terminated in 2015"),
            new("cdl.anti-spam.org.cn", enabled: false, comment: "Inactive")
        };

        public DNSBLAnalysis() {
        }

        internal List<string> DNSBLLists => DnsblEntries
            .Where(e => e.Enabled)
            .Select(e => e.Domain)
            .ToList();

        /// <summary>Gets a value indicating whether any query returned a listing.</summary>
        public bool IsBlacklisted => Results.Any(r => r.Value.IsBlacklisted);
        /// <summary>Gets the number of hosts or addresses checked.</summary>
        public int RecordChecked => Results.Count;
        /// <summary>Gets the count of hosts that were listed.</summary>
        public int Blacklisted => Results.Count(r => r.Value.IsBlacklisted);
        /// <summary>Gets the count of hosts that were not listed.</summary>
        public int NotBlacklisted => Results.Count(r => !r.Value.IsBlacklisted);

        /// <summary>Gets the per-host DNSBL query results.</summary>
        public Dictionary<string, DNSQueryResult> Results { get; set; } = new Dictionary<string, DNSQueryResult>();

        /// <summary>Gets a flattened list of all DNSBL records returned.</summary>
        public List<DNSBLRecord> AllResults { get; private set; } = new List<DNSBLRecord>();

        internal InternalLogger Logger { get; set; }

        /// <summary>
        /// Clears cached results allowing the instance to be reused.
        /// </summary>
        public void Reset() {
            Results = new Dictionary<string, DNSQueryResult>();
            AllResults = new List<DNSBLRecord>();
            Logger = null;
        }

        internal async Task AnalyzeDNSBLRecordsMX(string domainName, InternalLogger logger) {
            Reset();
            Logger = logger;

            var mxRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX);

            Logger.WriteVerbose($"Checking {domainName} against {DNSBLLists.Count} blacklists");
            var resultsDomain = await ToListAsync(QueryDNSBL(DNSBLLists, domainName));
            ConvertToResults(domainName, resultsDomain);

            Logger.WriteVerbose($"Checking {domainName} MX records against {DNSBLLists.Count} blacklists");
            foreach (var mxRecord in mxRecords) {
                // Extract the IP address from the MX record data
                string domainRecord = mxRecord.Data.Split(' ')[1];

                var dnsResponse = await DnsConfiguration.QueryDNS(domainRecord, DnsRecordType.A);
                foreach (var response in dnsResponse) {
                    var ipAddress = response.Data;
                    // Perform the DNSBL check for the IP address

                    Logger.WriteVerbose($"Checking {ipAddress} (MX record resolved) against {DNSBLLists.Count} blacklists");
                    var results = await ToListAsync(QueryDNSBL(DNSBLLists, ipAddress));

                    //// Add the MX record data to each DNSBLRecord
                    //foreach (var result in results) {
                    //    result.FQDN = mxRecord.Data;
                    //}

                    //DNSQueryResult queryResult = new DNSQueryResult {
                    //    Host = domainRecord,
                    //    DNSBLRecords = results,
                    //};
                    //Results[ipAddress] = queryResult;

                    ConvertToResults(ipAddress, results);
                }
            }
        }

        /// <summary>
        /// Queries the configured DNSBL providers for the specified host or IP address.
        /// </summary>
        /// <param name="ipAddressOrHostname">Address or hostname to query.</param>
        /// <param name="logger">Logger for verbose output.</param>
        /// <returns>Enumeration of <see cref="DNSBLRecord"/> objects.</returns>
        public async IAsyncEnumerable<DNSBLRecord> AnalyzeDNSBLRecords(string ipAddressOrHostname, InternalLogger logger) {
            Reset();
            Logger = logger;
            Logger.WriteVerbose($"Checking {ipAddressOrHostname} against {DNSBLLists.Count} blacklists");
            var collected = new List<DNSBLRecord>();
            await foreach (var record in QueryDNSBL(DNSBLLists, ipAddressOrHostname)) {
                collected.Add(record);
                yield return record;
            }
            ConvertToResults(ipAddressOrHostname, collected);
        }

        private void ConvertToResults(string ipAddressOrHostname, IEnumerable<DNSBLRecord> results) {
            DNSQueryResult queryResult = new DNSQueryResult {
                Host = ipAddressOrHostname,
                DNSBLRecords = results,
            };
            if (Results.ContainsKey(ipAddressOrHostname)) {
                Results.Remove(ipAddressOrHostname);
            }
            Results[ipAddressOrHostname] = queryResult;
            AllResults.AddRange(results);
        }

        private static async Task<List<T>> ToListAsync<T>(IAsyncEnumerable<T> source) {
            var list = new List<T>();
            await foreach (var item in source) {
                list.Add(item);
            }
            return list;
        }

        private static readonly Dictionary<string, (bool IsListed, string Meaning)> _generalReplyCodes = new()
        {
            ["127.0.0.1"] = (false, "Whitelisted"),
            ["127.0.0.2"] = (true, "Blacklisted"),
            ["127.0.0.3"] = (true, "Blacklisted"),
            ["127.0.0.4"] = (true, "Blacklisted")
        };

        private static readonly Dictionary<string, Dictionary<string, (bool IsListed, string Meaning)>> _providerReplyCodes = new(StringComparer.OrdinalIgnoreCase)
        {
            ["hostkarma.junkemailfilter.com"] = new()
            {
                ["127.0.0.1"] = (false, "Whitelisted"),
                ["127.0.0.2"] = (true, "Blacklisted"),
                ["127.0.0.4"] = (false, "Whitelisted")
            }
        };

        private static (bool IsListed, string Meaning) GetReplyCodeMeaning(string blacklist, string reply) {
            if (string.IsNullOrEmpty(reply)) {
                return (false, string.Empty);
            }

            if (reply.StartsWith("127.255.")) {
                return (false, "Reserved");
            }

            if (_providerReplyCodes.TryGetValue(blacklist, out var providerMap) &&
                providerMap.TryGetValue(reply, out var providerResult)) {
                return providerResult;
            }

            if (_generalReplyCodes.TryGetValue(reply, out var result)) {
                return result;
            }

            return reply.StartsWith("127.") ? (true, "Listed") : (true, string.Empty);
        }

        private async IAsyncEnumerable<DNSBLRecord> QueryDNSBL(IEnumerable<string> dnsblList, string ipAddressOrHostname) {

            // Check if the input is an IP address or a hostname
            string name;
            if (IPAddress.TryParse(ipAddressOrHostname, out IPAddress ipAddress)) {
                name = ipAddress.ToPtrFormat();
            } else {
                // Use the hostname and append the DNSBL list
                name = ipAddressOrHostname;
            }

            List<string> queries = new List<string>();
            foreach (var dnsbl in dnsblList) {
                string query = $"{name}.{dnsbl}";
                Logger?.WriteVerbose($"Querying blacklist domain {dnsbl} with query {query}");
                queries.Add(query);
            }

            var responses = new Dictionary<string, List<DnsAnswer>>();

            var resultA = await DnsConfiguration.QueryFullDNS(queries.ToArray(), DnsRecordType.A);
            foreach (var dnsResponse in resultA) {
                responses[dnsResponse.Questions[0].Name] = dnsResponse.Answers.ToList();
            }

            if (IPAddress.TryParse(ipAddressOrHostname, out IPAddress ip) && ip.AddressFamily == AddressFamily.InterNetworkV6) {
                var resultAaaa = await DnsConfiguration.QueryFullDNS(queries.ToArray(), DnsRecordType.AAAA);
                foreach (var dnsResponse in resultAaaa) {
                    if (!responses.ContainsKey(dnsResponse.Questions[0].Name)) {
                        responses[dnsResponse.Questions[0].Name] = dnsResponse.Answers.ToList();
                    } else {
                        responses[dnsResponse.Questions[0].Name].AddRange(dnsResponse.Answers);
                    }
                }
            }

            foreach (var pair in responses) {
                if (pair.Value.Count == 0) {
                    var dnsblRecord = new DNSBLRecord {
                        IPAddress = name,
                        OriginalIPAddress = ipAddressOrHostname,
                        FQDN = pair.Key,
                        BlackList = pair.Key.Substring(name.Length + 1),
                        IsBlackListed = false,
                        Answer = string.Empty,
                        ReplyMeaning = string.Empty,
                    };
                    yield return dnsblRecord;
                } else {
                    foreach (var record in pair.Value) {
                        var dnsblRecord = new DNSBLRecord {
                            IPAddress = name,
                            OriginalIPAddress = ipAddressOrHostname,
                            FQDN = record.Name,
                            BlackList = record.Name.Substring(name.Length + 1),
                            IsBlackListed = true,
                            Answer = record.Data,
                        };

                        var info = GetReplyCodeMeaning(dnsblRecord.BlackList, dnsblRecord.Answer);
                        dnsblRecord.IsBlackListed = info.IsListed;
                        dnsblRecord.ReplyMeaning = info.Meaning;

                        yield return dnsblRecord;
                    }
                }
            }
        }

        /// <summary>
        /// Adds a DNSBL provider to the internal list if not already present.
        /// </summary>
        /// <param name="dnsbl">Blacklist host name.</param>
        /// <param name="enabled">Whether the entry should be queried.</param>
        /// <param name="comment">Optional descriptive comment.</param>
        public void AddDNSBL(string dnsbl, bool enabled = true, string comment = null) {
            if (string.IsNullOrWhiteSpace(dnsbl))
                return;

            if (!DnsblEntries.Any(e => StringComparer.OrdinalIgnoreCase.Equals(e.Domain, dnsbl))) {
                DnsblEntries.Add(new DnsblEntry(dnsbl, enabled, comment));
            }
        }

        /// <summary>Gets a read only view of configured DNSBL providers.</summary>
        public IReadOnlyList<DnsblEntry> GetDNSBL() {
            return DnsblEntries.AsReadOnly();
        }

        /// <summary>
        /// Adds multiple DNSBL providers.
        /// </summary>
        /// <param name="dnsbls">Collection of DNSBL host names.</param>
        public void AddDNSBL(IEnumerable<string> dnsbls) {
            foreach (var dnsbl in dnsbls) {
                AddDNSBL(dnsbl);
            }
        }

        /// <summary>
        /// Removes a DNSBL provider from the list if it exists.
        /// </summary>
        /// <param name="dnsbl">Blacklist host name.</param>
        public void RemoveDNSBL(string dnsbl) {
            var entry = DnsblEntries.FirstOrDefault(e =>
                string.Equals(e.Domain, dnsbl, StringComparison.OrdinalIgnoreCase));
            if (entry != null) {
                DnsblEntries.Remove(entry);
            }
        }

        /// <summary>Clears all configured DNSBL providers.</summary>
        public void ClearDNSBL() {
            DnsblEntries.Clear();
        }

        /// <summary>
        /// Loads DNSBL entries from a simple text file.
        /// </summary>
        /// <param name="filePath">File containing provider domains.</param>
        /// <param name="clearExisting">When set to <c>true</c> existing entries are removed before loading.</param>
        public void LoadDNSBL(string filePath, bool clearExisting = false) {
            if (string.IsNullOrWhiteSpace(filePath)) {
                throw new ArgumentException("File path cannot be null or whitespace.", nameof(filePath));
            }
            if (!File.Exists(filePath)) {
                throw new FileNotFoundException($"DNSBL list file not found: {filePath}");
            }

            var lines = File.ReadAllLines(filePath, Encoding.UTF8);

            if (clearExisting) {
                ClearDNSBL();
            }

            foreach (var line in lines) {
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed))
                    continue;

                bool enabled = true;
                if (trimmed.StartsWith("#")) {
                    enabled = false;
                    trimmed = trimmed.Substring(1).Trim();
                }

                string comment = null;
                var commentIndex = trimmed.IndexOf('#');
                if (commentIndex >= 0) {
                    comment = trimmed.Substring(commentIndex + 1).Trim();
                    trimmed = trimmed.Substring(0, commentIndex).Trim();
                }

                trimmed = trimmed.TrimEnd('#').Trim();

                if (!string.IsNullOrWhiteSpace(trimmed)) {
                    AddDNSBL(trimmed, enabled, comment);
                }
            }
        }

        /// <summary>
        /// Loads DNSBL configuration from a JSON file.
        /// </summary>
        /// <param name="filePath">Path to JSON configuration file.</param>
        /// <param name="overwriteExisting">Replace existing entries if they already exist.</param>
        /// <param name="clearExisting">Remove existing entries before loading.</param>
        public void LoadDnsblConfig(string filePath, bool overwriteExisting = false, bool clearExisting = false) {
            if (string.IsNullOrWhiteSpace(filePath)) {
                throw new ArgumentException("File path cannot be null or whitespace.", nameof(filePath));
            }
            if (!File.Exists(filePath)) {
                throw new FileNotFoundException($"DNSBL config file not found: {filePath}");
            }

            var json = File.ReadAllText(filePath);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var config = JsonSerializer.Deserialize<DnsblConfiguration>(json, options);

            if (config == null || config.Providers == null)
                return;

            if (clearExisting) {
                ClearDNSBL();
            }

            foreach (var provider in config.Providers) {
                var existing = DnsblEntries.FirstOrDefault(e => StringComparer.OrdinalIgnoreCase.Equals(e.Domain, provider.Domain));
                if (existing == null) {
                    DnsblEntries.Add(new DnsblEntry(provider.Domain, provider.Enabled, provider.Comment));
                } else if (overwriteExisting) {
                    existing.Enabled = provider.Enabled;
                    existing.Comment = provider.Comment;
                }
            }
        }
    }
}