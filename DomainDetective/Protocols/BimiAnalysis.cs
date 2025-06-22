using DnsClientX;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace DomainDetective {
    /// <summary>
    /// Analyse BIMI records according to draft specifications.
    /// </summary>
    public class BimiAnalysis {
        public string BimiRecord { get; private set; }
        public bool BimiRecordExists { get; private set; }
        public bool StartsCorrectly { get; private set; }
        public string Location { get; private set; }
        public string Authority { get; private set; }
        public bool LocationUsesHttps { get; private set; }
        public bool AuthorityUsesHttps { get; private set; }
        public bool DeclinedToPublish { get; private set; }
        public bool SvgFetched { get; private set; }
        public bool SvgValid { get; private set; }

        public async Task AnalyzeBimiRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            await Task.Yield();

            BimiRecord = null;
            BimiRecordExists = false;
            StartsCorrectly = false;
            Location = null;
            Authority = null;
            LocationUsesHttps = false;
            AuthorityUsesHttps = false;
            DeclinedToPublish = false;
            SvgFetched = false;
            SvgValid = false;

            var recordList = dnsResults.ToList();
            BimiRecordExists = recordList.Any();
            if (!BimiRecordExists) {
                logger.WriteVerbose("No BIMI record found.");
                return;
            }

            BimiRecord = string.Join(" ", recordList.Select(r => r.Data));
            logger.WriteVerbose($"Analyzing BIMI record {BimiRecord}");

            StartsCorrectly = BimiRecord.StartsWith("v=BIMI1", StringComparison.OrdinalIgnoreCase);

            foreach (var part in BimiRecord.Split(';')) {
                var kv = part.Split(new[] { '=' }, 2);
                if (kv.Length != 2) {
                    continue;
                }

                var key = kv[0].Trim();
                var value = kv[1].Trim();

                switch (key) {
                    case "l":
                        Location = value;
                        break;
                    case "a":
                        Authority = value;
                        break;
                }
            }

            LocationUsesHttps = string.IsNullOrEmpty(Location) || Location.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            AuthorityUsesHttps = string.IsNullOrEmpty(Authority) || Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

            DeclinedToPublish = string.IsNullOrEmpty(Location) && string.IsNullOrEmpty(Authority);

            if (!string.IsNullOrEmpty(Location) && LocationUsesHttps) {
                var svg = await DownloadIndicator(Location, logger);
                if (svg != null) {
                    SvgFetched = true;
                    SvgValid = ValidateSvg(svg);
                }
            }
        }

        private static async Task<string> DownloadIndicator(string url, InternalLogger logger) {
            try {
                using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
                using (HttpClient client = new HttpClient(handler)) {
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
                    using (var response = await client.GetAsync(url)) {
                        if (!response.IsSuccessStatusCode) {
                            return null;
                        }

                        var bytes = await response.Content.ReadAsByteArrayAsync();
                        if (url.EndsWith(".svgz", StringComparison.OrdinalIgnoreCase)) {
                            using (var ms = new MemoryStream(bytes))
                            using (var gz = new GZipStream(ms, CompressionMode.Decompress))
                            using (var reader = new StreamReader(gz)) {
                                return await reader.ReadToEndAsync();
                            }
                        }
                        return System.Text.Encoding.UTF8.GetString(bytes);
                    }
                }
            } catch (Exception ex) {
                logger?.WriteError("Error downloading BIMI indicator {0}: {1}", url, ex.Message);
                return null;
            }
        }

        private static bool ValidateSvg(string svgContent) {
            try {
                var doc = XDocument.Parse(svgContent);
                return doc.Root?.Name.LocalName.Equals("svg", StringComparison.OrdinalIgnoreCase) == true;
            } catch {
                return false;
            }
        }
    }
}