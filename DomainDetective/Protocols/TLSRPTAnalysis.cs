using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Mail;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes SMTP TLS Reporting (TLSRPT) policies according to RFC 8460.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
public class TLSRPTAnalysis : IHasAssessments {
        /// <summary>The concatenated TLSRPT record.</summary>
        public string? TlsRptRecord { get; private set; }

        /// <summary>Indicates whether a TLSRPT record exists.</summary>
        public bool TlsRptRecordExists { get; private set; }

        /// <summary>Indicates whether multiple records were found.</summary>
        public bool MultipleRecords { get; private set; }

        /// <summary>Indicates whether the record starts with v=TLSRPTv1.</summary>
        public bool StartsCorrectly { get; private set; }

        /// <summary>True when at least one RUA destination is defined.</summary>
        public bool RuaDefined { get; private set; }
        public List<string> MailtoRua { get; private set; } = new();
        public List<string> HttpRua { get; private set; } = new();
        public List<string> InvalidRua { get; private set; } = new();
        public List<string> UnknownTags { get; private set; } = new();

        public bool PolicyValid => TlsRptRecordExists && StartsCorrectly && RuaDefined;

        /// <summary>Optional: when true, attempts a lightweight HEAD to HTTPS RUA endpoints to verify reachability.</summary>
        public bool CheckEndpoints { get; set; }
        /// <summary>HTTP status per HTTPS RUA endpoint (when CheckEndpoints = true).</summary>
        public Dictionary<string, int> RuaHttpStatus { get; private set; } = new();

        /// <summary>Relevant standards for TLSRPT analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "SMTP TLS Reporting", Reference = "RFC 8460", Url = "https://datatracker.ietf.org/doc/html/rfc8460" }
        };

        /// <summary>Structured assessments captured during TLSRPT analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        public async Task AnalyzeTlsRptRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger, CancellationToken cancellationToken = default) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "TLSRPT");
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
            RuaHttpStatus = new Dictionary<string, int>(System.StringComparer.OrdinalIgnoreCase);

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
                logger?.WriteWarningCode(TlsRptCodes.MissingRua, "TLSRPT record missing rua tag.");
            }

            if (CheckEndpoints && HttpRua.Count > 0)
            {
                await ValidateHttpRuaAsync(logger, cancellationToken);
            }
        }

        private static readonly HttpClient _httpClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 });
        private async Task ValidateHttpRuaAsync(InternalLogger logger, CancellationToken ct)
        {
            foreach (var url in HttpRua)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Head, url);
                    using var resp = await _httpClient.SendAsync(req, ct).ConfigureAwait(false);
                    RuaHttpStatus[url] = (int)resp.StatusCode;
                    if ((int)resp.StatusCode >= 400)
                    {
                        logger?.WriteWarningCode(TlsRptCodes.RuaHttpError, "TLSRPT HTTPS RUA responded with {0}: {1}", (int)resp.StatusCode, url);
                    }
                }
                catch (Exception ex)
                {
                    RuaHttpStatus[url] = 0;
                    logger?.WriteWarningCode(TlsRptCodes.RuaHttpUnreachable, "TLSRPT HTTPS RUA unreachable: {0} ({1})", url, ex.Message);
                }
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
