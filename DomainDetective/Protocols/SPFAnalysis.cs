using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Globalization;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using DomainDetective.Helpers;

namespace DomainDetective {
    /// <summary>
    ///
    /// To validate an SPF record according to the RFC 7208 standard, you would need to check for several things.Here are some of the key points:
    /// 1.	The SPF record must start with "v=spf1".
    /// 2.	The SPF record should not exceed 10 DNS lookups - SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check, including any lookups caused by the use of the "include" mechanism or the "redirect" modifier.  If this number is exceeded during a check, a PermError MUST be returned.  The "include", "a", "mx", "ptr", and "exists" mechanisms as well as the "redirect" modifier do count against this limit.  The "all", "ip4", and "ip6" mechanisms do not require DNS lookups and therefore do not count against this limit. The "exp" modifier does not count against this limit because the DNS lookup to fetch the explanation string occurs after the SPF record has been evaluated.
    /// 3.	The SPF record should not have more than one "all" mechanism.
    /// 4.	The total length of the SPF record should stay below 512 bytes when possible.
    /// 5.	Each TXT chunk of the SPF record must be 255 bytes or less.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public partial class SpfAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        internal DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>DNS TTL (seconds) of the SPF TXT record as returned by DNS.</summary>
        public int? DnsRecordTtl { get; private set; }
        /// <summary>TTL (seconds) of the CNAME record when this record was resolved via CNAME alias.</summary>
        public int? CnameTtl { get; private set; }
        /// <summary>True when the SPF record was resolved through a CNAME alias.</summary>
        public bool IsCnameResolved { get; private set; }

        /// <summary>Combined SPF record text.</summary>
        public string SpfRecord { get; private set; } = string.Empty;
        public List<string> SpfRecords { get; private set; } = new List<string>();
        public bool SpfRecordExists { get; private set; } // should be true
        public bool MultipleSpfRecords { get; private set; } // should be false
        public bool StartsCorrectly { get; private set; } // should be true
        public bool ExceedsTotalCharacterLimit { get; private set; } // should be false
        public bool ExceedsCharacterLimit { get; private set; } // should be false
        public List<string> DnsLookups { get; private set; } = new List<string>();
        public int DnsLookupsCount { get; private set; }
        public bool ExceedsDnsLookups { get; private set; } // should be false
        public bool MultipleAllMechanisms { get; private set; } // should be false
        public bool ContainsCharactersAfterAll { get; private set; }
        public bool HasPtrType { get; private set; }
        public bool HasNullLookups { get; private set; }
        public bool HasRedirect { get; private set; }
        public bool HasExp { get; private set; }
        public bool InvalidIpSyntax { get; private set; }
        /// <summary>True when the SPF policy appears to deny all sending (e.g., <c>v=spf1 -all</c> with no allow mechanisms).</summary>
        public bool DenyAll { get; private set; }
        public List<string> ARecords { get; private set; } = new List<string>();
        public List<string> Ipv4Records { get; private set; } = new List<string>();
        public List<string> Ipv6Records { get; private set; } = new List<string>();
        public List<string> MxRecords { get; private set; } = new List<string>();
        public List<string> PtrRecords { get; private set; } = new List<string>();
        public List<string> IncludeRecords { get; private set; } = new List<string>();
        public List<string> ExistsRecords { get; private set; } = new List<string>();
        public string? ExpValue { get; private set; }
        public string? RedirectValue { get; private set; }
        public string? AllMechanism { get; private set; }

        public List<string> ResolvedARecords { get; private set; } = new List<string>();
        public List<string> ResolvedIpv4Records { get; private set; } = new List<string>();
        public List<string> ResolvedIpv6Records { get; private set; } = new List<string>();
        public List<string> ResolvedMxRecords { get; private set; } = new List<string>();
        public List<string> ResolvedPtrRecords { get; private set; } = new List<string>();
        public List<string> ResolvedIncludeRecords { get; private set; } = new List<string>();
        public List<string> ResolvedExistsRecords { get; private set; } = new List<string>();

        public List<string> UnknownMechanisms { get; private set; } = new List<string>();

        public FlattenedSpfResult FlattenedIpAnalysis { get; private set; } = new FlattenedSpfResult();

        public Dictionary<string, string> TestSpfRecords { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public bool CycleDetected { get; private set; }
        public string? CyclePath { get; private set; }
        public bool PermError { get; private set; }
        public List<string> RedirectVisitedDomains { get; private set; } = new List<string>();
        private HashSet<string> _visitedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Summary message describing overall SPF status.</summary>
        public string Advisory { get; private set; } = string.Empty;


        public List<SpfPartAnalysis> SpfPartAnalyses { get; private set; } = new List<SpfPartAnalysis>();
        public List<SpfTestResult> SpfTestResults { get; private set; } = new List<SpfTestResult>();
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        private const int MaxDnsLookups = 10;
        public int ExpDnsLookupsCount { get; private set; }
        public bool ExpExceedsDnsLookups { get; private set; }
        private readonly List<string> _warnings = new();
        public IReadOnlyList<string> Warnings => _warnings;
        // Debug visibility of tokenizer output
        public IReadOnlyList<string> DebugTokens { get; private set; } = Array.Empty<string>();
        public string DebugAllAfterParts { get; private set; } = string.Empty;
        public string DebugAllAfterFallback { get; private set; } = string.Empty;

        /// <summary>Structured assessments captured during SPF analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Actionable recommendations derived from assessments.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>
        /// True when SPF configuration effectively authorizes outbound senders
        /// after resolving include/redirect chains as per RFC 7208.
        /// </summary>
        public bool EffectiveSpfSends { get; private set; }

        /// <summary>Relevant standards for SPF analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "Sender Policy Framework", Reference = "RFC 7208", Url = "https://datatracker.ietf.org/doc/html/rfc7208" }
        };

        private static readonly Regex MacroRegex = new(
            @"%\{(?<letter>[slodipvhcrt])(?<digits>\d{1,2})?(?<reverse>r)?(?<delims>[.\-+,/_=]*)\}",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static bool DebugSpf => Environment.GetEnvironmentVariable("DD_DEBUG_SPF") == "1";

        public void Reset() {
            SpfRecord = string.Empty;
            SpfRecords = new List<string>();
            SpfRecordExists = false;
            DnsRecordTtl = null;
            CnameTtl = null;
            IsCnameResolved = false;
            MultipleSpfRecords = false;
            StartsCorrectly = false;
            ExceedsTotalCharacterLimit = false;
            ExceedsCharacterLimit = false;
            DnsLookups = new List<string>();
            DnsLookupsCount = 0;
            ExceedsDnsLookups = false;
            MultipleAllMechanisms = false;
            ContainsCharactersAfterAll = false;
            HasPtrType = false;
            HasNullLookups = false;
            HasRedirect = false;
            HasExp = false;
            InvalidIpSyntax = false;
            CycleDetected = false;
            CyclePath = null;
            PermError = false;
            RedirectVisitedDomains = new List<string>();
            _visitedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ARecords = new List<string>();
            Ipv4Records = new List<string>();
            Ipv6Records = new List<string>();
            MxRecords = new List<string>();
            PtrRecords = new List<string>();
            IncludeRecords = new List<string>();
            ExistsRecords = new List<string>();
            ResolvedARecords = new List<string>();
            ResolvedIpv4Records = new List<string>();
            ResolvedIpv6Records = new List<string>();
            ResolvedMxRecords = new List<string>();
            ResolvedPtrRecords = new List<string>();
            ResolvedIncludeRecords = new List<string>();
            ResolvedExistsRecords = new List<string>();
            UnknownMechanisms = new List<string>();
            FlattenedIpAnalysis = new FlattenedSpfResult();
            ExpValue = null;
            RedirectValue = null;
            AllMechanism = null;
            SpfPartAnalyses = new List<SpfPartAnalysis>();
            SpfTestResults = new List<SpfTestResult>();
            _warnings.Clear();
            ExpDnsLookupsCount = 0;
            ExpExceedsDnsLookups = false;
            Advisory = string.Empty;
            EffectiveSpfSends = false;
        }

        public async Task AnalyzeSpfRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "SPF", target: Subject);
            Reset();
            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }
            var spfRecordList = dnsResults.ToList();

            // Capture CNAME TTL before filtering
            var cnameRecords = spfRecordList.Where(r => r.Type == DnsRecordType.CNAME).ToList();
            if (cnameRecords.Any()) {
                IsCnameResolved = true;
                CnameTtl = cnameRecords.Min(r => r.TTL);
            }

            var txtRecords = spfRecordList.Where(r => r.Type != DnsRecordType.CNAME).ToList();
            DnsRecordTtl = DnsAnswerTtlHelper.MinPositiveTtl(txtRecords, expectedType: DnsRecordType.TXT);
            SpfRecordExists = txtRecords.Any();
            MultipleSpfRecords = txtRecords.Count > 1;

            // create a list of strings from the list of DnsResult objects
            // we use DataStringsEscaped to get the escaped strings, as provided by DnsClientX
            // this will allow us to test if the record length exceeds 255 characters
            foreach (var record in txtRecords) {
                foreach (var chunk in record.DataStringsEscaped) {
                    SpfRecords.Add(TrimQuotes(chunk));
                }
            }
            WarnIfSpfRecordChunksTooLong(logger);
            // However for analysis we only need the record text. Prefer Data, but fall back to DataRaw when supplied directly (tests).
            if (txtRecords.Count == 1) {
                var first = txtRecords.First();
                SpfRecord = TrimQuotes(first.DataRaw ?? first.Data ?? string.Empty);
            } else {
                // if there are multiple records, we need to join them together to analyze them
                SpfRecord = string.Join(" ", SpfRecords);
            }

            logger.WriteVerbose($"Analyzing SPF record {SpfRecord}");

            // check the character limits
            CheckCharacterLimits(txtRecords);

            // check the SPF record starts correctly
            StartsCorrectly = StartsCorrectly || SpfRecord.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase);

            // Emit high-level assessments for presence/version/length
            if (!SpfRecordExists) {
                logger?.WriteWarningCode(SpfCodes.MissingRecord, "No SPF record found.");
            }
            if (MultipleSpfRecords) {
                logger?.WriteWarningCode(SpfCodes.MultipleRecords, "Multiple SPF records published.");
            }
            if (SpfRecordExists && !StartsCorrectly) {
                logger?.WriteWarningCode(SpfCodes.StartsInvalid, "SPF record does not start with v=spf1.");
            }
            if (ExceedsTotalCharacterLimit || ExceedsCharacterLimit) {
                logger?.WriteWarningCode(SpfCodes.RecordLengthExceeds, "SPF record length exceeds recommended limits (255 per chunk, ~512 total).");
            }

            // loop through the parts of the SPF record for remaining checks
            var parts = TokenizeSpfRecord(SpfRecord).ToArray();
            DebugTokens = parts;
            if (DebugSpf) {
                try { System.Console.Error.WriteLine($"[SPF DEBUG] StartsCorrectly={StartsCorrectly} SpfRecord='{SpfRecord}'"); } catch { }
            }
            if (DebugSpf) {
                try { System.Console.Error.WriteLine($"[SPF DEBUG] Record: '{SpfRecord}'\n[SPF DEBUG] Tokens: {string.Join("|", parts)}"); } catch { }
            }

            // check that the SPF record does not exceed 10 DNS lookups
            int dnsLookups = await CountDnsLookups(parts, _visitedDomains, new List<string>(), logger);
            DnsLookupsCount = dnsLookups;
            ExceedsDnsLookups = ExceedsDnsLookups || DnsLookupsCount > 10;

            // check that the SPF record does not have more than one "all" mechanism
            MultipleAllMechanisms = MultipleAllMechanisms || CountAllMechanisms(parts) > 1;

            if (MultipleAllMechanisms) {
                logger?.WriteWarningCode(SpfCodes.AllMultiple, "SPF contains multiple 'all' mechanisms; only the last is effective.");
            }

            // add the parts to the appropriate lists with provenance
            foreach (var part in parts) {
                AddPartToList(part, logger, Subject, 0, Array.Empty<string>());
            }
            DebugAllAfterParts = AllMechanism ?? string.Empty;

            // check if the SPF record contains characters after "all"
            ContainsCharactersAfterAll = parts
                .Where(part => IsAllMechanism(part))
                .Any(part => !part.Equals(parts.Last(), StringComparison.OrdinalIgnoreCase));

            if (ContainsCharactersAfterAll) {
                logger?.WriteWarningCode(SpfCodes.AllTrailingContent, "SPF has mechanisms after 'all' that are never evaluated.");
            }

            // check if the SPF record contains a PTR type
            HasPtrType = PtrRecords.Any();
            if (HasPtrType) {
                logger?.WriteWarningCode(SpfCodes.PtrUsed, "SPF uses 'ptr' mechanism which is discouraged.");
            }

            // check if the SPF record contains exists: with no domain
            CheckForNullDnsLookups(parts);
            if (ExistsRecords.Count > 0) {
                logger?.WriteWarningCode(SpfCodes.ExistsUsed, "SPF uses 'exists' which can be expensive and unpredictable.");
            }

            // keep TestSpfRecords intact so subsequent operations like
            // GetFlattenedSpf can resolve fake DNS records in unit tests

            WarnIfExceedsDnsLookups(logger);

            // Robustly determine terminal all-mechanism from raw record tokens in case tokenizer splits quoted segments oddly
            try {
                var rawTokens = (SpfRecord ?? string.Empty)
                    .Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(t => t.Trim('"'))
                    .ToArray();
                // Find the last occurrence of an all-mechanism token without relying on Reverse()
                var rawAll = rawTokens.LastOrDefault(t => IsAllMechanism(t));
                if (!string.IsNullOrWhiteSpace(rawAll)) {
                    AllMechanism = rawAll;
                }
                DebugAllAfterFallback = AllMechanism ?? string.Empty;
                if (DebugSpf) {
                    try { System.Console.Error.WriteLine($"[SPF DEBUG] RawTokens: {string.Join("|", rawTokens)} | All={AllMechanism}"); } catch { }
                }
            } catch { /* best-effort */ }

            UpdateAdvisory(logger);

            // Detect deny-all posture: no allow mechanisms and terminal -all.
            try {
                bool allow = Ipv4Records.Count > 0 || Ipv6Records.Count > 0 || ARecords.Count > 0 || MxRecords.Count > 0 ||
                            PtrRecords.Count > 0 || ExistsRecords.Count > 0 || IncludeRecords.Count > 0 || HasRedirect;
                DenyAll = SpfRecordExists && !allow && AllMechanism?.Equals("-all", StringComparison.OrdinalIgnoreCase) == true;
            } catch {
                DenyAll = false;
            }

            // policy strength advisory for 'all'
            if (string.IsNullOrWhiteSpace(AllMechanism)) {
                logger?.WriteWarningCode(SpfCodes.AllMissing, "No terminal '-all' mechanism present; consider adding '-all'.");
            } else if (!AllMechanism!.Equals("-all", StringComparison.OrdinalIgnoreCase)) {
                logger?.WriteWarningCode(SpfCodes.AllSoft, $"SPF ends with '{AllMechanism}'. Consider '-all' once senders are validated.");
            }

            // Build provenance tree for mechanisms (top-level + includes/redirects)
            try { await PopulateProvenanceAsync(Subject ?? string.Empty, logger); } catch { /* best-effort */ }
        }

    }

    /// <summary>
    /// Holds details about a parsed part of an SPF record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SpfPartAnalysis {
        public string Prefix { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string PrefixDesc { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string? Provider { get; set; }
        /// <summary>Domain record where the token was found (top-level or included).</summary>
        public string? SourceDomain { get; set; }
        /// <summary>Include/redirect nesting depth starting from the subject domain.</summary>
        public int Depth { get; set; }
        /// <summary>Traversal chain of domains that led to this token.</summary>
        public List<string> Chain { get; set; } = new List<string>();
    }

    /// <summary>
    /// Result of evaluating an IP/sender/HELO against an SPF policy.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public sealed class SpfHostEvaluation
    {
        /// <summary>Evaluated domain.</summary>
        public string Subject { get; set; } = string.Empty;
        /// <summary>Tested IP address.</summary>
        public string IpAddress { get; set; } = string.Empty;
        /// <summary>Sender used for macro expansion.</summary>
        public string Sender { get; set; } = string.Empty;
        /// <summary>HELO/EHLO name used for macro expansion.</summary>
        public string Helo { get; set; } = string.Empty;
        /// <summary>Final result: pass, fail, softfail, neutral, or permerror.</summary>
        public string Verdict { get; set; } = string.Empty;
        /// <summary>Token from the policy that matched and determined the verdict.</summary>
        public string? MatchedToken { get; set; }
        /// <summary>Mechanism/modifier type that matched (ip4, ip6, a, mx, exists, include, all).</summary>
        public string? MatchedType { get; set; }
        /// <summary>Domain whose record contained the matching token.</summary>
        public string? MatchedDomain { get; set; }
        /// <summary>Traversal chain for includes/redirects that led to the match.</summary>
        public List<string> Chain { get; set; } = new List<string>();
        /// <summary>Total DNS lookups used during evaluation.</summary>
        public int DnsLookups { get; set; }
        /// <summary>True when the 10‑lookup limit was exceeded.</summary>
        public bool LookupsExceeded { get; set; }
    }

    /// <summary>
    /// Result of a single SPF validation test.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SpfTestResult {
        public string Test { get; set; } = string.Empty;
        public string Result { get; set; } = string.Empty;
        public string Assessment { get; set; } = string.Empty;
    }

    /// <summary>
    /// Details of flattened SPF IP addresses including deduplication information.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class FlattenedSpfResult {
        public string? Subject { get; set; }
        public List<string> Tokens { get; set; } = new List<string>();
        public Dictionary<string, List<string>> TokenIpMap { get; set; } = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        public List<string> UniqueIps { get; set; } = new List<string>();
        public List<string> DuplicateIps { get; set; } = new List<string>();
    }
}
