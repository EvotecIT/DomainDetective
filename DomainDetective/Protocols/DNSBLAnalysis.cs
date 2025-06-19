using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.IO;
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

    public class DnsblEntry {
        public string Domain { get; set; }
        public bool Enabled { get; set; } = true;
        public string Comment { get; set; }

        public DnsblEntry() {}
        public DnsblEntry(string domain, bool enabled = true, string comment = null) {
            Domain = domain;
            Enabled = enabled;
            Comment = comment;
        }
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
        internal List<DnsblEntry> DnsblEntries { get; } = new();

        private static readonly string DefaultListPath = Path.Combine(AppContext.BaseDirectory, "Dictionaries", "dnsbl.txt");

        public DNSBLAnalysis()
        {
            if (File.Exists(DefaultListPath))
            {
                LoadDNSBL(DefaultListPath);
            }
        }

        internal List<string> DNSBLLists => DnsblEntries
            .Where(e => e.Enabled)
            .Select(e => e.Domain)
            .ToList();

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
            Logger.WriteVerbose($"Checking {ipAddressOrHostname} against {DNSBLLists.Count} blacklists");
            var results = await QueryDNSBL(DNSBLLists, ipAddressOrHostname);
            ConvertToResults(ipAddressOrHostname, results);
        }

        private void ConvertToResults(string ipAddressOrHostname, IEnumerable<DNSBLRecord> results) {
            DNSQueryResult queryResult = new DNSQueryResult {
                Host = ipAddressOrHostname,
                DNSBLRecords = results,
            };
            Results[ipAddressOrHostname] = queryResult;
        }

        private async Task<IEnumerable<DNSBLRecord>> QueryDNSBL(IEnumerable<string> dnsblList, string ipAddressOrHostname) {
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
                    //Logger.WriteVerbose($"Record {dnsblRecord.FQDN} on {dnsblRecord.BlackList}, is blacklisted: {dnsblRecord.IsBlackListed}");
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
                        //Logger.WriteVerbose($"Record {dnsblRecord.FQDN} on {dnsblRecord.BlackList}, is blacklisted: {dnsblRecord.IsBlackListed}");
                    }

                }
            }
            return results.OrderByDescending(r => r.IsBlackListed).ToList();
        }

        public void AddDNSBL(string dnsbl, bool enabled = true, string comment = null)
        {
            if (string.IsNullOrWhiteSpace(dnsbl))
                return;

            if (!DnsblEntries.Any(e => e.Domain == dnsbl))
            {
                DnsblEntries.Add(new DnsblEntry(dnsbl, enabled, comment));
            }
        }

        public void AddDNSBL(IEnumerable<string> dnsbls)
        {
            foreach (var dnsbl in dnsbls)
            {
                AddDNSBL(dnsbl);
            }
        }

        public void RemoveDNSBL(string dnsbl)
        {
            var entry = DnsblEntries.FirstOrDefault(e => e.Domain == dnsbl);
            if (entry != null)
            {
                DnsblEntries.Remove(entry);
            }
        }

        public void ClearDNSBL()
        {
            DnsblEntries.Clear();
        }

        public void LoadDNSBL(string filePath, bool clearExisting = false)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"DNSBL list file not found: {filePath}");
            }

            var lines = File.ReadAllLines(filePath);

            if (clearExisting)
            {
                ClearDNSBL();
            }

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed))
                    continue;

                bool enabled = true;
                if (trimmed.StartsWith("#"))
                {
                    enabled = false;
                    trimmed = trimmed.Substring(1).Trim();
                }

                string comment = null;
                var commentIndex = trimmed.IndexOf('#');
                if (commentIndex >= 0)
                {
                    comment = trimmed.Substring(commentIndex + 1).Trim();
                    trimmed = trimmed.Substring(0, commentIndex).Trim();
                }

                if (!string.IsNullOrWhiteSpace(trimmed))
                {
                    AddDNSBL(trimmed, enabled, comment);
                }
            }
        }
    }
}
