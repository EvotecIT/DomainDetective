using DnsClientX;
using DomainDetective.Definitions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective {
    /// <summary>
    /// Performs DKIM record and key validation checks.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// DKIM selectors are queried for public keys and the syntax and key size
    /// are validated. Additional ADSP records are also parsed when present.
    /// </remarks>
    public partial class DkimAnalysis : IHasAssessments {
        /// <summary>DNS configuration used for auxiliary lookups (e.g., CNAME for provider mapping).</summary>
        public DnsConfiguration? DnsConfiguration { get; set; }
        /// <summary>Maximum number of DKIM selector DNS queries issued concurrently.</summary>
        public int SelectorQueryConcurrency { get; set; } = 8;
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>Minimum allowed RSA key size in bits.</summary>
        public const int MinimumRsaKeyBits = 1024;
        /// <summary>Gets the analysis results keyed by selector.</summary>
        public Dictionary<string, DkimRecordAnalysis> AnalysisResults { get; private set; } = new Dictionary<string, DkimRecordAnalysis>();
        /// <summary>Threshold for raising key age warnings.</summary>
        public TimeSpan KeyAgeWarningThreshold { get; set; } = TimeSpan.FromDays(365);
        /// <summary>Gets the ADSP record text when present.</summary>
        public string? AdspRecord { get; private set; }
        /// <summary>Gets a value indicating whether an ADSP record exists.</summary>
        public bool AdspRecordExists { get; private set; }

        /// <summary>Summary message describing DKIM validation outcome.</summary>
        public string Advisory { get; private set; } = string.Empty;

        /// <summary>Relevant standards for DKIM analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "DomainKeys Identified Mail", Reference = "RFC 6376", Url = "https://datatracker.ietf.org/doc/html/rfc6376" }
        };

        /// <summary>Structured assessments captured during DKIM analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Actionable recommendations derived from assessments.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>Clears <see cref="AnalysisResults"/>.</summary>
        public void Reset() {
            AnalysisResults = new Dictionary<string, DkimRecordAnalysis>();
            AdspRecord = null;
            AdspRecordExists = false;
            Advisory = string.Empty;
        }

        /// <summary>
        /// Analyses DKIM TXT records for the specified selector.
        /// </summary>
        /// <param name="selector">DKIM selector being processed.</param>
        /// <param name="dnsResults">TXT records from the DNS query.</param>
        /// <param name="logger">Logger used for verbose output.</param>
        public async Task AnalyzeDkimRecords(string selector, IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DKIM", target: selector);
            await Task.Yield(); // To avoid warning about lack of 'await'

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var dkimRecordList = dnsResults.ToList();

            // Capture CNAME TTL before filtering
            var cnameRecords = dkimRecordList.Where(r => r.Type == DnsRecordType.CNAME).ToList();
            var txtRecords = dkimRecordList.Where(r => r.Type != DnsRecordType.CNAME).ToList();

            var analysis = new DkimRecordAnalysis {
                DkimRecordExists = txtRecords.Any(),
                ValidKeyType = true,
                ValidFlags = true
            };

            if (cnameRecords.Any()) {
                analysis.IsCnameResolved = true;
                analysis.CnameTtl = cnameRecords.Min(r => r.TTL);
            }

            analysis.DnsRecordTtl = DnsAnswerTtlHelper.MinPositiveTtl(txtRecords, expectedType: DnsRecordType.TXT);

            analysis.MultipleRecords = txtRecords.Count > 1;

            // A DKIM key is one TXT resource record. Character-strings within that
            // resource record are concatenated without separators by DNS.
            foreach (var record in txtRecords) {
                if (string.IsNullOrEmpty(analysis.Name) && !string.IsNullOrEmpty(record.Name)) {
                    analysis.Name = record.Name;
                }
            }

            if (txtRecords.Count > 0) {
                var record = txtRecords[0];
                analysis.DkimRecord = record.TxtConcatenatedData;
            }

            if (string.IsNullOrWhiteSpace(analysis.Name) && !string.IsNullOrWhiteSpace(Subject)) {
                analysis.Name = $"{selector}._domainkey.{Subject}";
            }

            logger.WriteVerbose($"Analyzing DKIM record {analysis.DkimRecord}");

            if (!analysis.DkimRecordExists) {
                logger?.WriteWarningCode(DkimCodes.RecordMissing, "No DKIM record found for selector {0}.", selector);
                AnalysisResults[selector] = analysis;
                UpdateAdvisory(logger);
                return;
            }

            if (string.IsNullOrWhiteSpace(analysis.DkimRecord)) {
                logger?.WriteWarningCode(DkimCodes.RecordMissing, "DKIM record for selector {0} exists but is empty.", selector);
                AnalysisResults[selector] = analysis;
                UpdateAdvisory(logger);
                return;
            }

            if (analysis.MultipleRecords) {
                logger?.WriteErrorCode(DkimCodes.MultipleRecords, "Multiple DKIM TXT records found for selector {0}; a unique key record is required.", selector);
            }

            var tags = analysis.DkimRecord.Split(';');
            analysis.VersionTagPresent = tags.Any(tag => tag.TrimStart().StartsWith("v=", StringComparison.OrdinalIgnoreCase));
            analysis.StartsCorrectly = analysis.DkimRecord.TrimStart().StartsWith("v=DKIM1", StringComparison.OrdinalIgnoreCase);
            analysis.VersionValid = !analysis.VersionTagPresent || analysis.StartsCorrectly;

            // loop through the tags of the DKIM record
            foreach (var tag in tags) {
                var keyValue = tag.Split(new[] { '=' }, 2);
                if (keyValue.Length == 2) {
                    var key = keyValue[0].Trim();
                    var value = keyValue[1].Trim();
                    switch (key) {
                        case "p":
                            analysis.PublicKey = value;
                            break;
                        case "s":
                            analysis.ServiceType = value;
                            break;
                        case "t":
                            analysis.Flags = value;
                            analysis.UnknownFlagCharacters = new string(value.ToLowerInvariant().Where(c => c != 'y' && c != 's').ToArray());
                            analysis.ValidFlags = analysis.UnknownFlagCharacters.Length == 0;
                            break;
                        case "k":
                            analysis.KeyType = value;
                            analysis.ValidKeyType = string.Equals(value, "rsa", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(value, "ed25519", StringComparison.OrdinalIgnoreCase);
                            break;
                        case "c":
                            analysis.Canonicalization = value;
                            var parts = value.ToLowerInvariant().Split('/');
                            analysis.ValidCanonicalization = parts.Length is 1 or 2;
                            foreach (var part in parts)
                            {
                                if (part != "simple" && part != "relaxed")
                                {
                                    analysis.ValidCanonicalization = false;
                                    if (!analysis.UnknownCanonicalizationModes.Contains(part))
                                    {
                                        analysis.UnknownCanonicalizationModes.Add(part);
                                        logger?.WriteErrorCode(DkimCodes.CanonicalizationUnknown, "Unknown canonicalization mode: {0}", part);
                                    }
                                }
                            }
                            break;
                        case "h":
                            analysis.HashAlgorithm = value;
                            if (value.IndexOf("sha1", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                analysis.DeprecatedTags.Add($"h={value}");
                                logger?.WriteWarningCode(DkimCodes.HashDeprecated, "Deprecated hash algorithm detected: {0}", value);
                            }
                            break;
                        case "a":
                            analysis.SignatureAlgorithm = value;
                            break;
                        case "g":
                            analysis.DeprecatedTags.Add("g");
                            logger?.WriteWarningCode(DkimCodes.TagGDeprecated, "DKIM tag 'g' is deprecated and ignored");
                            break;
                        case "q":
                            analysis.DeprecatedTags.Add("q");
                            logger?.WriteWarningCode(DkimCodes.TagQDeprecated, "DKIM tag 'q' is deprecated and ignored");
                            break;
                    }
                }
            }

            // check the public key exists
            analysis.PublicKeyExists = !string.IsNullOrEmpty(analysis.PublicKey);
            analysis.KeyTypeExists = !string.IsNullOrEmpty(analysis.KeyType);
            analysis.KeyType = analysis.KeyTypeExists ? analysis.KeyType : "rsa";
            analysis.ValidKeyType = string.Equals(analysis.KeyType, "rsa", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(analysis.KeyType, "ed25519", StringComparison.OrdinalIgnoreCase);
            ValidatePublicKey(selector, analysis, logger);

            AnalysisResults[selector] = analysis;
            // Info-level positives (posture signals)
            if (analysis.DkimRecordExists)
                logger?.WriteInformationCode(DkimCodes.RecordPresent, "DKIM record present for selector {0}", selector);
            if (analysis.StartsCorrectly)
                logger?.WriteInformationCode(DkimCodes.RecordStartsV1, "DKIM starts with v=DKIM1 for selector {0}", selector);
            if (analysis.PublicKeyExists)
                logger?.WriteInformationCode(DkimCodes.PublicKeyPresent, "DKIM public key present for selector {0}", selector);
            if (analysis.ValidRsaKeyLength && analysis.KeyLength >= 2048)
                logger?.WriteInformationCode(DkimCodes.KeyStrong, "DKIM RSA key length {0} bits for selector {1}", analysis.KeyLength, selector);
            if (analysis.ValidKeyType)
                logger?.WriteInformationCode(DkimCodes.KeyTypeValid, "DKIM key type valid: {0}", analysis.KeyType ?? "unknown");
            if (analysis.ValidCanonicalization && !string.IsNullOrWhiteSpace(analysis.Canonicalization))
                logger?.WriteInformationCode(DkimCodes.CanonicalizationValid, "DKIM canonicalization valid: {0}", analysis.Canonicalization);
            var hashAlgorithm = analysis.HashAlgorithm;
            if (hashAlgorithm != null && hashAlgorithm.IndexOf("sha256", StringComparison.OrdinalIgnoreCase) >= 0)
                logger?.WriteInformationCode(DkimCodes.HashSha256, "DKIM hash algorithm includes sha256 for selector {0}", selector);
            if (analysis.ValidFlags)
                logger?.WriteInformationCode(DkimCodes.FlagsValid, "DKIM flags valid for selector {0}", selector);
            if (!string.IsNullOrWhiteSpace(analysis.SignatureAlgorithm) &&
                (analysis.SignatureAlgorithm.Equals("rsa-sha256", StringComparison.OrdinalIgnoreCase) ||
                 analysis.SignatureAlgorithm.Equals("ed25519-sha256", StringComparison.OrdinalIgnoreCase)))
                logger?.WriteInformationCode(DkimCodes.AlgorithmRecommended, "DKIM signature algorithm {0} for selector {1}", analysis.SignatureAlgorithm, selector);
            if (IsValidKeyRecord(analysis))
                logger?.WriteInformationCode(DkimCodes.PublicKeyValid, "DKIM selector {0} publishes valid {1} public key material", selector, analysis.KeyType);

            // Provider mapping via CNAME target when available (best-effort)
            try
            {
                var name = analysis.Name;
                if (DnsConfiguration != null && name != null && !string.IsNullOrWhiteSpace(name))
                {
                    var cname = await DnsConfiguration.QueryDNS(name.TrimEnd('.'), DnsRecordType.CNAME);
                    if (cname != null && cname.Length > 0)
                    {
                        var target = cname[0].Data?.Trim('.') ?? string.Empty;
                        if (!string.IsNullOrEmpty(target))
                        {
                            analysis.CnameTarget = target;
                            analysis.Provider = DKIMProviders.ProviderForDomain(target);
                        }
                    }
                }
                // If still unknown, try to infer from record name (rare)
                analysis.Provider ??= DKIMProviders.ProviderForDomain(analysis.Name);
            }
            catch { }

            UpdateAdvisory(logger);
        }

        private void UpdateAdvisory(InternalLogger? logger) {
            if (AnalysisResults.Count == 0) {
                Advisory = "No DKIM selectors analyzed.";
                return;
            }

            var issues = AnalysisResults
                .Where(kvp => !IsValidKeyRecord(kvp.Value) || kvp.Value.WeakKey)
                .Select(kvp => kvp.Key)
                .ToArray();

            if (issues.Length > 0) {
                Advisory = $"Issues detected with selector(s): {string.Join(", ", issues)}.";
            } else {
                Advisory = "All DKIM selectors appear valid.";
                logger?.WriteInformationCode(DkimCodes.SelectorsValid, "All discovered DKIM selector key records are valid");
            }

            // Key reuse detection across selectors (same fingerprint)
            try {
                var duplicates = AnalysisResults
                    .Where(kvp => kvp.Value.ValidPublicKey && !string.IsNullOrWhiteSpace(kvp.Value.KeyFingerprint))
                    .GroupBy(kvp => kvp.Value!.KeyFingerprint!, StringComparer.OrdinalIgnoreCase)
                    .Where(g => g.Count() > 1);
                foreach (var g in duplicates) {
                    var sels = string.Join(", ", g.Select(x => x.Key));
                    logger?.WriteWarningCode(DkimCodes.KeyReused, "DKIM key reused by selectors: {0}", sels);
                }
            } catch { }
        }

        /// <summary>
        /// Processes ADSP TXT records.
        /// </summary>
        /// <param name="dnsResults">TXT answers from the DNS query.</param>
        /// <param name="logger">Logger used for warnings.</param>
        public async Task AnalyzeAdspRecord(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DKIM");
            await Task.Yield();

            AdspRecord = null;
            AdspRecordExists = false;

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var records = dnsResults.ToList();
            AdspRecordExists = records.Any();
            if (!AdspRecordExists) {
                return;
            }

            var chunks = records
                .Select(r => r.Data)
                .Where(d => !string.IsNullOrEmpty(d))
                .ToList();

            if (!chunks.Any()) {
                return;
            }

            AdspRecord = string.Join(" ", chunks);
            logger?.WriteWarningCode(DkimCodes.AdspObsolete, "ADSP record found but ADSP is obsolete.");
        }

        /// <summary>
        /// Queries well known selector names and analyses any discovered records.
        /// </summary>
        /// <param name="domainName">Domain to query.</param>
        /// <param name="dnsConfiguration">DNS configuration to use.</param>
        /// <param name="logger">Logger for verbose messages.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The selector that returned a record, or <see langword="null"/>.</returns>
        public async Task<string?> QueryWellKnownSelectors(string domainName, DnsConfiguration dnsConfiguration, InternalLogger logger, CancellationToken cancellationToken = default) {
            Reset();
            logger.WriteVerbose("Auto-detecting DKIM selectors for {0}", domainName);
            var adsp = await dnsConfiguration.QueryDNS(
                $"_adsp._domainkey.{domainName}",
                DnsRecordType.TXT,
                filter: string.Empty,
                includeAliasesInFilter: true,
                cancellationToken: cancellationToken);
            if (adsp.Any()) {
                await AnalyzeAdspRecord(adsp, logger);
            }

            string? firstFound = null;
            var found = new List<string>();
            var selectors = DKIMSelectors.GuessSelectors().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var results = new DnsAnswer[selectors.Length][];
            using var concurrency = new SemaphoreSlim(Math.Max(1, SelectorQueryConcurrency));
            var queries = selectors.Select(async (selector, index) => {
                logger.WriteVerbose("Trying DKIM selector '{0}'", selector);
                await concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
                try {
                    results[index] = await dnsConfiguration.QueryDNS(
                        $"{selector}._domainkey.{domainName}",
                        DnsRecordType.TXT,
                        "DKIM1",
                        includeAliasesInFilter: true,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                } finally {
                    concurrency.Release();
                }
            }).ToArray();
            await Task.WhenAll(queries).ConfigureAwait(false);

            for (var index = 0; index < selectors.Length; index++) {
                var selector = selectors[index];
                var dkim = results[index] ?? Array.Empty<DnsAnswer>();
                if (dkim.Any()) {
                    logger.WriteVerbose("Found DKIM record with selector '{0}'", selector);
                    await AnalyzeDkimRecords(selector, dkim, logger);
                    firstFound ??= selector;
                    found.Add(selector);
                }
            }

            if (found.Count == 0) {
                logger.WriteVerbose("No DKIM records found in built-in selector list.");
            } else {
                logger.WriteVerbose("Auto-detection discovered {0} selector(s): {1}", found.Count, string.Join(", ", found));
            }

            return firstFound;
        }
    }

    /// <summary>
    /// Detailed information about a DKIM record evaluation.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DkimRecordAnalysis {
        /// <summary>Gets or sets the queried record name.</summary>
        public string? Name { get; set; }
        /// <summary>Gets or sets the full DKIM record text.</summary>
        public string DkimRecord { get; set; } = string.Empty;
        /// <summary>Gets or sets a value indicating whether the record exists.</summary>
        public bool DkimRecordExists { get; set; }
        /// <summary>Gets or sets a value indicating whether more than one TXT resource record was returned.</summary>
        public bool MultipleRecords { get; set; }
        /// <summary>Gets or sets a value indicating whether the record starts with <c>v=DKIM1</c>.</summary>
        public bool StartsCorrectly { get; set; }
        /// <summary>Gets or sets a value indicating whether an explicit version tag was present.</summary>
        public bool VersionTagPresent { get; set; }
        /// <summary>Gets or sets a value indicating whether the optional version tag is absent or valid and first.</summary>
        public bool VersionValid { get; set; }
        /// <summary>Gets or sets a value indicating whether the public key value was present.</summary>
        public bool PublicKeyExists { get; set; }
        /// <summary>Gets or sets a value indicating whether a key type was specified.</summary>
        public bool ValidPublicKey { get; set; }
        /// <summary>True when the RSA key length meets <see cref="DkimAnalysis.MinimumRsaKeyBits"/>.</summary>
        public bool ValidRsaKeyLength { get; set; }
        /// <summary>True when key material has the required length for its declared key type.</summary>
        public bool ValidKeyLength { get; set; }
        /// <summary>Length of the RSA public key in bits.</summary>
        public int KeyLength { get; set; }
        /// <summary>True when the RSA key length is under 2048 bits.</summary>
        public bool WeakKey { get; set; }
        /// <summary>Indicates whether the <c>k</c> tag was present.</summary>
        public bool KeyTypeExists { get; set; }
        /// <summary>Gets or sets a value indicating whether the key type is recognized.</summary>
        public bool ValidKeyType { get; set; }
        /// <summary>Gets or sets the public key.</summary>
        public string PublicKey { get; set; } = string.Empty;
        /// <summary>Gets or sets the service type flag.</summary>
        public string ServiceType { get; set; } = string.Empty;
        /// <summary>Gets or sets any flags defined for the record.</summary>
        public string? Flags { get; set; }
        /// <summary>Gets unrecognized flag characters if <see cref="ValidFlags"/> is <c>false</c>.</summary>
        public string UnknownFlagCharacters { get; set; } = string.Empty;
        /// <summary>Gets or sets a value indicating whether all flag characters are valid.</summary>
        public bool ValidFlags { get; set; }
        /// <summary>Unrecognized canonicalization modes.</summary>
        public List<string> UnknownCanonicalizationModes { get; } = new();
        /// <summary>Lists deprecated tags or values detected in the record.</summary>
        public List<string> DeprecatedTags { get; } = new();
        /// <summary>Canonicalization modes specified in the record.</summary>
        public string Canonicalization { get; set; } = string.Empty;
        /// <summary>Gets a value indicating whether the canonicalization string is valid.</summary>
        public bool ValidCanonicalization { get; set; }
        /// <summary>Gets or sets the key type.</summary>
        public string KeyType { get; set; } = string.Empty;
        /// <summary>Gets or sets the hash algorithm type.</summary>
        public string? HashAlgorithm { get; set; }
        /// <summary>Gets or sets the signature algorithm.</summary>
        public string SignatureAlgorithm { get; set; } = string.Empty;
        /// <summary>Date the record appears to have been created.</summary>
        public DateTime? CreationDate { get; set; }
        /// <summary>Age of the key in days when <see cref="CreationDate"/> is known.</summary>
        public int KeyAgeDays { get; set; }
        /// <summary>True when <see cref="CreationDate"/> is over 12 months old.</summary>
        public bool OldKey { get; set; }
        /// <summary>SHA-256 fingerprint of the DKIM public key (DER bytes).</summary>
        public string? KeyFingerprint { get; set; }
        /// <summary>Provider inferred from CNAME target or name suffix (best-effort).</summary>
        public string? Provider { get; set; }
        /// <summary>Resolved CNAME target (when present).</summary>
        public string? CnameTarget { get; set; }
        /// <summary>DNS TTL (seconds) of the selector TXT record as returned by DNS.</summary>
        public int? DnsRecordTtl { get; set; }
        /// <summary>TTL (seconds) of the CNAME record when this record was resolved via CNAME alias.</summary>
        public int? CnameTtl { get; set; }
        /// <summary>True when the DKIM record was resolved through a CNAME alias.</summary>
        public bool IsCnameResolved { get; set; }
    }

    internal static partial class DKIMProviders
    {
        private static readonly (string Suffix, string Provider)[] _providerSuffixes = new (string, string)[]
        {
            ("amazonses.com", "Amazon SES"),
            ("sendgrid.net", "SendGrid"),
            ("sparkpostmail.com", "SparkPost"),
            ("mandrillapp.com", "Mailchimp/Mandrill"),
            ("mailgun.org", "Mailgun"),
            ("pphosted.com", "Proofpoint"),
            ("mimecast.com", "Mimecast"),
            ("google.com", "Google Workspace"),
            ("googlemail.com", "Google Workspace"),
            ("outlook.com", "Microsoft 365"),
            ("protection.outlook.com", "Microsoft 365"),
            ("exclaimer.net", "Exclaimer"),
            ("cust.barracudanetworks.com", "Barracuda"),
            ("bnc3.mailjet.com", "Mailjet")
        };

        public static string? ProviderForDomain(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return null;
            var d = name!.Trim('.');
            foreach (var (suffix, provider) in _providerSuffixes)
            {
                if (DomainHelper.IsDomainOrSubdomainOf(d, suffix)) return provider;
            }
            return null;
        }
    }
}
