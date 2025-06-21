using DnsClientX;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    public class SOAAnalysis {
        public string DomainName { get; private set; }
        public string PrimaryNameServer { get; private set; }
        public string ResponsibleMailbox { get; private set; }
        public long SerialNumber { get; private set; }
        public int Refresh { get; private set; }
        public int Retry { get; private set; }
        public int Expire { get; private set; }
        public int Minimum { get; private set; }
        public bool RecordExists { get; private set; }

        public async Task AnalyzeSoaRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            await Task.Yield();

            DomainName = null;
            PrimaryNameServer = null;
            ResponsibleMailbox = null;
            SerialNumber = 0;
            Refresh = 0;
            Retry = 0;
            Expire = 0;
            Minimum = 0;
            RecordExists = false;

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
                long.TryParse(parts[2], out var serial);
                int.TryParse(parts[3], out var refresh);
                int.TryParse(parts[4], out var retry);
                int.TryParse(parts[5], out var expire);
                int.TryParse(parts[6], out var minimum);

                SerialNumber = serial;
                Refresh = refresh;
                Retry = retry;
                Expire = expire;
                Minimum = minimum;
            }

            logger?.WriteVerbose($"Analyzed SOA record {record.Data}");
        }
    }
}
