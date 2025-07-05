using DnsClientX;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Parses and validates SOA records for a domain.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SOAAnalysis {
        public string? DomainName { get; private set; }
        public string? PrimaryNameServer { get; private set; }
        public string? ResponsibleMailbox { get; private set; }
        public long SerialNumber { get; private set; }
        public bool SerialFormatValid { get; private set; }
        public string? SerialFormatSuggestion { get; private set; }
        public int Refresh { get; private set; }
        public int Retry { get; private set; }
        public int Expire { get; private set; }
        public int Minimum { get; private set; }
        public int NegativeCacheTtl { get; private set; }
        public bool RecordExists { get; private set; }

        /// <summary>
        /// Reads SOA records and populates analysis properties.
        /// </summary>
        public async Task AnalyzeSoaRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            await Task.Yield();

            DomainName = null;
            PrimaryNameServer = null;
            ResponsibleMailbox = null;
            SerialNumber = 0;
            SerialFormatValid = false;
            SerialFormatSuggestion = null;
            Refresh = 0;
            Retry = 0;
            Expire = 0;
            Minimum = 0;
            NegativeCacheTtl = 0;
            RecordExists = false;

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var soaRecordList = dnsResults.ToList();
            RecordExists = soaRecordList.Any();
            if (!RecordExists) {
                logger?.WriteVerbose("No SOA record found.");
                return;
            }

            var record = soaRecordList.First();
            DomainName = record.Name;

            var parts = record.Data?.Split(new[] { ' ' }, System.StringSplitOptions.RemoveEmptyEntries);
            if (parts?.Length >= 7) {
                PrimaryNameServer = parts[0].TrimEnd('.');
                ResponsibleMailbox = parts[1].TrimEnd('.');
                var serialText = parts[2];
                long.TryParse(serialText, out var serial);
                int.TryParse(parts[3], out var refresh);
                int.TryParse(parts[4], out var retry);
                int.TryParse(parts[5], out var expire);
                int.TryParse(parts[6], out var minimum);

                SerialNumber = serial;
                SerialFormatValid = Regex.IsMatch(serialText, "^\\d{10}$") &&
                    DateTime.TryParseExact(serialText.Substring(0, 8), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);
                if (!SerialFormatValid) {
                    SerialFormatSuggestion = "Use YYYYMMDDnn serial format.";
                }
                Refresh = refresh;
                Retry = retry;
                Expire = expire;
                Minimum = minimum;
                NegativeCacheTtl = Math.Min(record.TTL, Minimum);
            }

            if (NegativeCacheTtl == 0) {
                NegativeCacheTtl = Math.Min(record.TTL, Minimum);
            }

            logger?.WriteVerbose($"Analyzed SOA record {record.Data}");
        }
    }
}