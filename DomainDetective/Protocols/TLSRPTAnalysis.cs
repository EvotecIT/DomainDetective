using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes SMTP TLS Reporting (TLSRPT) policies according to RFC 8460.
    /// </summary>
    public class TLSRPTAnalysis {
        public string? TlsRptRecord { get; private set; }
        public bool TlsRptRecordExists { get; private set; }
        public bool MultipleRecords { get; private set; }
        public bool StartsCorrectly { get; private set; }
        public bool RuaDefined { get; private set; }
        public List<string> MailtoRua { get; private set; } = new();
        public List<string> HttpRua { get; private set; } = new();
        public List<string> InvalidRua { get; private set; } = new();

        public bool PolicyValid => TlsRptRecordExists && StartsCorrectly && RuaDefined;

        public async Task AnalyzeTlsRptRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger, CancellationToken cancellationToken = default) {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();

            TlsRptRecord = null;
            TlsRptRecordExists = false;
            MultipleRecords = false;
            StartsCorrectly = false;
            RuaDefined = false;
            MailtoRua = new List<string>();
            HttpRua = new List<string>();
            InvalidRua = new List<string>();

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var recordList = dnsResults
                .Where(r => r.Type != DnsRecordType.CNAME)
                .ToList();
            TlsRptRecordExists = recordList.Any();
            MultipleRecords = recordList.Count > 1;
            if (!TlsRptRecordExists) {
                logger?.WriteVerbose("No TLSRPT record found.");
                return;
            }

            TlsRptRecord = string.Join(" ", recordList.Select(r => r.Data));
            logger?.WriteVerbose($"Analyzing TLSRPT record {TlsRptRecord}");

            StartsCorrectly = TlsRptRecord?.StartsWith("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase) == true;

            foreach (var part in (TlsRptRecord ?? string.Empty).Split(';')) {
                var kv = part.Split(new[] { '=' }, 2);
                if (kv.Length != 2) {
                    continue;
                }

                var key = kv[0].Trim();
                var value = kv[1].Trim();
                switch (key) {
                    case "rua":
                        RuaDefined = true;
                        AddUriToList(value, MailtoRua, HttpRua, InvalidRua);
                        break;
                }
            }
        }

        private void AddUriToList(string uri, List<string> mailtoList, List<string> httpList, List<string> invalidList) {
            var uris = uri.Split(',');
            foreach (var u in uris) {
                if (u.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) {
                    mailtoList.Add(u.Substring(7));
                } else if (u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
                    httpList.Add(u);
                } else {
                    invalidList.Add(u);
                }
            }
        }
    }
}