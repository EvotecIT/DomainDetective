using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes SMTP TLS Reporting (TLSRPT) policies according to RFC 8460.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class TLSRPTAnalysis {
        public string? TlsRptRecord { get; private set; }
        public bool TlsRptRecordExists { get; private set; }
        public bool MultipleRecords { get; private set; }
        public bool StartsCorrectly { get; private set; }
        public bool RuaDefined { get; private set; }
        public List<string> MailtoRua { get; private set; } = new();
        public List<string> HttpRua { get; private set; } = new();
        public List<string> InvalidRua { get; private set; } = new();
        public List<string> UnknownTags { get; private set; } = new();

        public bool PolicyValid => TlsRptRecordExists && StartsCorrectly && RuaDefined;

        public async Task AnalyzeTlsRptRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();

            TlsRptRecord = null;
            TlsRptRecordExists = false;
            MultipleRecords = false;
            StartsCorrectly = false;
            RuaDefined = false;
            MailtoRua = new List<string>();
            HttpRua = new List<string>();
            InvalidRua = new List<string>();
            UnknownTags = new List<string>();

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
                if (kv.Length == 2) {
                    var key = kv[0].Trim();
                    var value = kv[1].Trim();
                    switch (key.ToLowerInvariant()) {
                        case "rua":
                            RuaDefined = true;
                            AddUriToList(value, MailtoRua, HttpRua, InvalidRua);
                            break;
                        case "v":
                            break;
                        default:
                            var tagPair = $"{key}={value}";
                            if (!UnknownTags.Contains(tagPair)) {
                                UnknownTags.Add(tagPair);
                            }
                            break;
                    }
                } else {
                    var unknown = part.Trim();
                    if (!string.IsNullOrEmpty(unknown) && !UnknownTags.Contains(unknown)) {
                        UnknownTags.Add(unknown);
                    }
                }
            }

            if (!RuaDefined) {
                logger?.WriteWarning("TLSRPT record missing rua tag.");
            }
        }

        private void AddUriToList(string uri, List<string> mailtoList, List<string> httpList, List<string> invalidList) {
            var uris = uri.Split(',');
            foreach (var raw in uris) {
                var u = raw.Trim();
                if (u.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) {
                    var part = u.Substring(7);
                    try {
                        var decoded = Uri.UnescapeDataString(part);
                        _ = new MailAddress(decoded);
                        mailtoList.Add(decoded);
                    } catch {
                        invalidList.Add(u);
                    }
                } else if (Uri.TryCreate(u, UriKind.Absolute, out var parsed) &&
                           parsed.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) {
                    httpList.Add(u);
                } else {
                    invalidList.Add(u);
                }
            }
        }
    }
}