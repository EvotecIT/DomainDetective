using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace DomainDetective.PowerShell {
    /// <summary>Parses DMARC aggregate XML reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Summarize aggregate reports.</summary>
    ///   <code>Get-ChildItem ./reports/*.xml | Test-DmarcAggregate</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DmarcAggregate")]
    public sealed class CmdletTestDmarcAggregate : AsyncPSCmdlet {
        /// <param name="Path">Path to the aggregate report.</param>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; }

        protected override Task ProcessRecordAsync() {
            var summaries = ParseReport(Path);
            WriteObject(summaries, true);
            return Task.CompletedTask;
        }

        private static IEnumerable<DmarcAggregateSummary> ParseReport(string path) {
            string xmlText;
            if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) {
                using var file = File.OpenRead(path);
                using var gz = new GZipStream(file, CompressionMode.Decompress);
                using var reader = new StreamReader(gz);
                xmlText = reader.ReadToEnd();
            } else {
                xmlText = File.ReadAllText(path);
            }
            XDocument doc = XDocument.Parse(xmlText);
            string defaultDomain = doc.Root?.Element("policy_published")?.Element("domain")?.Value ?? string.Empty;
            var table = new Dictionary<string, DmarcAggregateSummary>(StringComparer.OrdinalIgnoreCase);
            foreach (var record in doc.Descendants("record")) {
                string domain = record.Element("identifiers")?.Element("header_from")?.Value ?? defaultDomain;
                if (string.IsNullOrEmpty(domain)) {
                    continue;
                }
                if (!table.TryGetValue(domain, out var summary)) {
                    summary = new DmarcAggregateSummary { Domain = domain };
                    table.Add(domain, summary);
                }
                int count = int.TryParse(record.Element("row")?.Element("count")?.Value, out var c) ? c : 0;
                summary.TotalCount += count;
                string dkim = record.Element("row")?.Element("policy_evaluated")?.Element("dkim")?.Value;
                string spf = record.Element("row")?.Element("policy_evaluated")?.Element("spf")?.Value;
                bool pass = string.Equals(dkim, "pass", StringComparison.OrdinalIgnoreCase) || string.Equals(spf, "pass", StringComparison.OrdinalIgnoreCase);
                if (pass) {
                    summary.PassCount += count;
                } else {
                    summary.FailCount += count;
                }
            }
            return table.Values.OrderBy(s => s.Domain);
        }
    }

    /// <summary>Summarized DMARC aggregate statistics for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public sealed class DmarcAggregateSummary {
        /// <summary>Domain name the statistics apply to.</summary>
        public string Domain { get; set; }

        /// <summary>Total messages seen for the domain.</summary>
        public int TotalCount { get; set; }

        /// <summary>Messages passing DMARC evaluation.</summary>
        public int PassCount { get; set; }

        /// <summary>Messages failing DMARC evaluation.</summary>
        public int FailCount { get; set; }
    }
}
