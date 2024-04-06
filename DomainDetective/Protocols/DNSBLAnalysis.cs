using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective {
    public class DNSBLRecord {
        public string IPAddress { get; set; }
        public string FQDN { get; set; }
        public string BlackList { get; set; }
        //public string BlackListReason { get; set; }
        public bool IsBlackListed { get; set; }
        public string Answer { get; set; }
        //public string NameServer { get; set; }
    }

    public class DNSQueryResult {
        public string Host { get; set; }
        public IEnumerable<DNSBLRecord> DNSBLRecords { get; set; }
        public int Listed => DNSBLRecords.Count(record => record.IsBlackListed);

        public List<string> ListedBlacklist => DNSBLRecords.Where(record => record.IsBlackListed).Select(record => record.BlackList).ToList();

        public int NotListed => DNSBLRecords.Count(record => !record.IsBlackListed);
        public int Total => DNSBLRecords.Count();
        public bool IsBlacklisted => Listed > 0;
    }

    public class DNSBLAnalysis {
        internal DnsConfiguration DnsConfiguration { get; set; }

        /// <summary>
        /// Gets the DNSBL lists.
        /// TODO: Move this to a configuration file?
        /// TODO: Add a method to add custom DNSBL lists.
        /// TODO: Add a method to remove DNSBL lists.
        /// TODO: Add a method to clear all DNSBL lists.
        /// TODO: Add a method to load DNSBL lists from a file.
        /// TODO: Define list as objects with information about the DNSBL list, and how to get off the list.
        /// </summary>
        /// <value>
        /// The DNSBL lists.
        /// </value>
        internal List<string> DNSBLLists { get; } = [
            "all.s5h.net",
            "auth.spamrats.com",
            "b.barracudacentral.org",
            "bad.virusfree.cz",
            "badconf.rhsbl.sorbs.net",
            "bip.virusfree.cz",
            "bl.0spam.org",
            "bl.blocklist.de",
            "bl.deadbeef.com",
            "bl.mailspike.org",
            "bl.nordspam.com",
            "bl.spamcop.net",
            "black.dnsbl.brukalai.lt",
            "black.mail.abusix.zone",
            "blackholes.five-ten-sg.com",
            "blacklist.woody.ch",
            "block.dnsbl.sorbs.net",
            "bogons.cymru.com",
            "cbl.abuseat.org",
            "combined.abuse.ch",
            "combined.mail.abusix.zone",
            "combined.rbl.msrbl.net",
            "db.wpbl.info",
            "dbl.0spam.org",
            "dbl.nordspam.com",
            "dbl.spamhaus.org",
            "dblack.mail.abusix.zone",
            "diskhash.mail.abusix.zone",
            "dnsbl.cyberlogic.net",
            "dnsbl.dronebl.org",
            "dnsbl.inps.de",
            "dnsbl.justspam.org",
            "dnsbl.sorbs.net",
            "dnsbl-1.uceprotect.net",
            "dnsbl-2.uceprotect.net",
            "dnsbl-3.uceprotect.net",
            "drone.abuse.ch",
            "duinv.aupads.org",
            "dul.dnsbl.sorbs.net",
            "dul.ru",
            "dyna.spamrats.com",
            "dynamic.mail.abusix.zone",
            "escalations.dnsbl.sorbs.net",
            "exploit.mail.abusix.zone",
            "hbl.spamhaus.org",
            "hostkarma.junkemailfilter.com",
            "http.dnsbl.sorbs.net",
            "images.rbl.msrbl.net",
            "ips.backscatterer.org",
            "ix.dnsbl.manitu.net",
            "key.authbl.dq.spamhaus.net",
            "korea.services.net",
            "misc.dnsbl.sorbs.net",
            "nbl.0spam.org",
            "new.spam.dnsbl.sorbs.net",
            "nod.mail.abusix.zone",
            "nomail.rhsbl.sorbs.net",
            "noptr.spamrats.com",
            "noservers.dnsbl.sorbs.net",
            "ohps.dnsbl.net.au",
            "old.spam.dnsbl.sorbs.net",
            "omrs.dnsbl.net.au",
            "orvedb.aupads.org",
            "osps.dnsbl.net.au",
            "osrs.dnsbl.net.au",
            "owfs.dnsbl.net.au",
            "owps.dnsbl.net.au",
            "pbl.spamhaus.org",
            "phishing.rbl.msrbl.net",
            "probes.dnsbl.net.au",
            "proxy.bl.gweep.ca",
            "proxy.block.transip.nl",
            "psbl.surriel.com",
            "rbl.0spam.org",
            "rbl.interserver.net",
            "rbl.metunet.com",
            "rdts.dnsbl.net.au",
            "recent.spam.dnsbl.sorbs.net",
            "relays.bl.gweep.ca",
            "relays.bl.kundenserver.de",
            "relays.nether.net",
            "residential.block.transip.nl",
            "rhsbl.sorbs.net",
            "ricn.dnsbl.net.au",
            "rmst.dnsbl.net.au",
            "safe.dnsbl.sorbs.net",
            "sbl.spamhaus.org",
            "short.rbl.jp",
            "shorthash.mail.abusix.zone",
            "singular.ttk.pte.hu",
            "smtp.dnsbl.sorbs.net",
            "socks.dnsbl.sorbs.net",
            "spam.abuse.ch",
            "spam.dnsbl.anonmails.de",
            "spam.dnsbl.sorbs.net",
            "spam.rbl.msrbl.net",
            "spam.spamrats.com",
            "spambot.bls.digibase.ca",
            "spamlist.or.kr",
            "spamrbl.imp.ch",
            "spamsources.fabel.dk",
            "t3direct.dnsbl.net.au",
            "ubl.lashback.com",
            "ubl.unsubscore.com",
            "virbl.bit.nl",
            "virus.rbl.jp",
            "virus.rbl.msrbl.net",
            "web.dnsbl.sorbs.net",
            "wormrbl.imp.ch",
            "xbl.spamhaus.org",
            "z.mailspike.net",
            "zen.spamhaus.org",
            "zombie.dnsbl.sorbs.net"
        ];

        public bool IsBlacklisted => Results.Any(r => r.Value.IsBlacklisted);
        public int RecordChecked => Results.Count;
        public int Blacklisted => Results.Count(r => r.Value.IsBlacklisted);
        public int NotBlacklisted => Results.Count(r => !r.Value.IsBlacklisted);

        public Dictionary<string, DNSQueryResult> Results { get; set; } = new Dictionary<string, DNSQueryResult>();

        internal InternalLogger Logger { get; set; }

        internal async Task AnalyzeDNSBLRecordsMX(string domainName, InternalLogger logger) {
            Logger = logger;
            List<DNSBLRecord> allResults = new List<DNSBLRecord>();

            var mxRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX);

            Logger.WriteVerbose($"Checking {domainName} against {DNSBLLists.Count} blacklists");
            var resultsDomain = await QueryDNSBL(DNSBLLists, domainName);
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
                    var results = await QueryDNSBL(DNSBLLists, ipAddress);

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



        internal async Task AnalyzeDNSBLRecords(string ipAddressOrHostname, InternalLogger logger) {
            Logger = logger;
            var results = await QueryDNSBL(DNSBLLists, ipAddressOrHostname);

            //DNSQueryResult queryResult = new DNSQueryResult {
            //    Host = ipAddressOrHostname,
            //    DNSBLRecords = results,
            //};
            //Results[ipAddressOrHostname] = queryResult;
            ConvertToResults(ipAddressOrHostname, results);
        }

        private void ConvertToResults(string ipAddressOrHostname, IEnumerable<DNSBLRecord> results) {
            DNSQueryResult queryResult = new DNSQueryResult {
                Host = ipAddressOrHostname,
                DNSBLRecords = results,
            };
            Results[ipAddressOrHostname] = queryResult;
        }

        private async Task<IEnumerable<DNSBLRecord>> QueryDNSBL(List<string> dnsblList, string ipAddressOrHostname) {
            List<DNSBLRecord> results = new List<DNSBLRecord>();

            // Check if the input is an IP address or a hostname
            string name;
            if (IPAddress.TryParse(ipAddressOrHostname, out IPAddress ipAddress)) {
                // Reverse the IP address and append the DNSBL list
                name = string.Join(".", ipAddress.ToString().Split('.').Reverse());
            } else {
                // Use the hostname and append the DNSBL list
                name = ipAddressOrHostname;
            }

            List<string> queries = new List<string>();
            foreach (var dnsbl in dnsblList) {
                string query = $"{name}.{dnsbl}";
                queries.Add(query);
            }

            var result = await DnsConfiguration.QueryFullDNS(queries.ToArray(), DnsRecordType.A);
            foreach (var dnsResponse in result) {
                if (dnsResponse.Answers.Length == 0) {
                    var dnsblRecord = new DNSBLRecord {
                        IPAddress = name,
                        FQDN = dnsResponse.Questions[0].Name,
                        BlackList = dnsResponse.Questions[0].Name.Substring(name.Length + 1), // Extract the blacklist name from the FQDN
                        IsBlackListed = false,
                        Answer = "",
                    };
                    results.Add(dnsblRecord);
                    Logger.WriteVerbose($"Record {dnsblRecord.FQDN} on {dnsblRecord.BlackList}, is blacklisted: {dnsblRecord.IsBlackListed}");
                } else {
                    foreach (var record in dnsResponse.Answers) {
                        var dnsblRecord = new DNSBLRecord {
                            IPAddress = name,
                            FQDN = record.Name,
                            BlackList = record.Name.Substring(name.Length + 1), // Extract the blacklist name from the FQDN
                            IsBlackListed = true,
                            Answer = record.Data,
                        };

                        // TODO: Add more blacklist specific checks, maybe move to a separate method for improved results
                        if (dnsblRecord.Answer.StartsWith("127.255.")) {
                            // Check if the answer is in the range 127.255.xx.xx
                            // https://www.spamhaus.org/faqs/dnsbl-usage/#200
                            // Return Code Zone Description
                            // 127.255.255.252 Any Typing error in DNSBL name
                            // 127.255.255.254 Any Query via public/open resolver
                            // 127.255.255.255	Any Excessive number of queries
                            dnsblRecord.IsBlackListed = false;
                        }

                        if (dnsblRecord.BlackList == "hostkarma.junkemailfilter.com") {
                            // https://wiki.junkemailfilter.com/index.php/Spam_DNS_Lists
                            // 127.0.0.1 - whilelist - trusted nonspam
                            // 127.0.0.2 - blacklist - block spam
                            // 127.0.0.3 - yellowlist - mix of spam and nonspam
                            // 127.0.0.4 - brownlist - all spam - but not yet enough to blacklist
                            // 127.0.0.5 - NOBL - This IP is not a spam only source and no blacklists need to be tested
                            if (dnsblRecord.Answer.StartsWith("127.0.0.2")) {
                                dnsblRecord.IsBlackListed = true;
                            } else {
                                dnsblRecord.IsBlackListed = false;
                            }
                        }

                        results.Add(dnsblRecord);
                        Logger.WriteVerbose($"Record {dnsblRecord.FQDN} on {dnsblRecord.BlackList}, is blacklisted: {dnsblRecord.IsBlackListed}");
                    }

                }
            }
            return results.OrderByDescending(r => r.IsBlackListed).ToList();
        }
    }
}
