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

        //Dictionary<string, string> KnownAnswers = new Dictionary<string, string> {
        //    { "127.0.0.2", "The IP address is a known source of spam" },
        //    { "127.0.0.3", "The IP address is a known source of phishing attacks" },
        //    // Add more known answers and reasons here
        //};

        public IEnumerable<DNSBLRecord> Results { get; set; }

        public async Task AnalyzeDNSBLRecords(IEnumerable<DnsAnswer> mxRecords, InternalLogger logger) {
            List<DNSBLRecord> allResults = new List<DNSBLRecord>();

            foreach (var mxRecord in mxRecords) {
                // Extract the IP address from the MX record data
                string ipAddress = mxRecord.Data.Split(' ')[1];

                // Perform the DNSBL check for the IP address
                var results = await QueryDNSBL(DNSBLLists, ipAddress);

                // Add the MX record data to each DNSBLRecord
                foreach (var result in results) {
                    result.FQDN = mxRecord.Data;
                }

                allResults.AddRange(results);
            }

            Results = allResults;
        }

        public async Task AnalyzeDNSBLRecords(string ipAddress) {
            Results = await QueryDNSBL(DNSBLLists, ipAddress);
        }

        private async Task<IEnumerable<DNSBLRecord>> QueryDNSBL(List<string> dnsblList, string ipAddress) {
            List<DNSBLRecord> results = new List<DNSBLRecord>();

            // Reverse the IP address and append the DNSBL list
            string reversedIp = string.Join(".", ipAddress.Split('.').Reverse());

            List<string> queries = new List<string>();
            foreach (var dnsbl in dnsblList) {
                string query = $"{reversedIp}.{dnsbl}";
                queries.Add(query);
            }

            var result = await DnsConfiguration.QueryFullDNS(queries.ToArray(), DnsRecordType.A);
            foreach (var dnsResponse in result) {
                if (dnsResponse.Answers.Length == 0) {
                    var dnsblRecord = new DNSBLRecord {
                        IPAddress = ipAddress,
                        FQDN = dnsResponse.Questions[0].Name,
                        BlackList = dnsResponse.Questions[0].Name.Substring(ipAddress.Length + 1), // Extract the blacklist name from the FQDN
                        IsBlackListed = false,
                        Answer = "",
                    };
                    results.Add(dnsblRecord);
                } else {
                    foreach (var record in dnsResponse.Answers) {
                        var dnsblRecord = new DNSBLRecord {
                            IPAddress = ipAddress,
                            FQDN = record.Name,
                            BlackList = record.Name.Substring(ipAddress.Length + 1), // Extract the blacklist name from the FQDN
                            IsBlackListed = true,
                            Answer = record.Data,
                        };
                        results.Add(dnsblRecord);
                    }
                }
            }
            return results.OrderByDescending(r => r.IsBlackListed).ToList();
        }
    }
}
