using DnsClientX;
using DomainDetective.Definitions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DomainDetective {
    /// <summary>
    /// Performs DKIM record and key validation checks.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// DKIM selectors are queried for public keys and the syntax and key size
    /// are validated. Additional ADSP records are also parsed when present.
    /// </remarks>
    public class DkimAnalysis : IHasAssessments {
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
        public string Advisory { get; private set; }

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
            var analysis = new DkimRecordAnalysis {
                DkimRecordExists = dkimRecordList.Any(),
                ValidKeyType = true,
                ValidFlags = true
            };

            // create a single string from the list of DnsResult objects
            foreach (var record in dkimRecordList) {
                if (string.IsNullOrEmpty(analysis.Name) && !string.IsNullOrEmpty(record.Name)) {
                    analysis.Name = record.Name;
                }
                if (record.DataStringsEscaped != null && record.DataStringsEscaped.Length > 0) {
                    analysis.DkimRecord += string.Join(string.Empty, record.DataStringsEscaped);
                } else {
                    analysis.DkimRecord += record.Data ?? record.DataRaw;
                }
            }

            logger.WriteVerbose($"Analyzing DKIM record {analysis.DkimRecord}");

            if (string.IsNullOrWhiteSpace(analysis.DkimRecord)) {
                return;
            }

            // check the DKIM record starts correctly
            analysis.StartsCorrectly = analysis.DkimRecord.StartsWith("v=DKIM1");

            // loop through the tags of the DKIM record
            var tags = analysis.DkimRecord.Split(';');
            foreach (var tag in tags) {
                var keyValue = tag.Split(new[] { '=' }, 2);
                if (keyValue.Length == 2) {
                    var key = keyValue[0].Trim();
                    var value = keyValue[1].Trim();
                    switch (key) {
                        case "p":
                            analysis.PublicKey = value;
                            try {
                                var b64 = (value ?? string.Empty).Trim();
                                b64 = b64.Replace("\r", string.Empty).Replace("\n", string.Empty).Replace(" ", string.Empty);
                                var mod = b64.Length % 4; if (mod > 0) b64 = b64 + new string('=', 4 - mod);
                                var bytes = Convert.FromBase64String(b64);
                                try {
                                    using var sha = System.Security.Cryptography.SHA256.Create();
                                    var fp = sha.ComputeHash(bytes);
                                    analysis.KeyFingerprint = System.BitConverter.ToString(fp).Replace("-", string.Empty);
                                } catch { }
                                try {
                                    var rsaKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(bytes);
                                    analysis.KeyLength = rsaKey.Modulus.BitLength;
                                    analysis.ValidRsaKeyLength = analysis.KeyLength >= MinimumRsaKeyBits;
                                    analysis.WeakKey = analysis.KeyLength > 0 && analysis.KeyLength < 2032;
                                    // Some providers publish SPKI blobs where modulus parsing may under-report size.
                                    // If decoded blob length strongly indicates a 2048-bit key, ensure WeakKey=false.
                                    if (analysis.WeakKey && bytes.Length >= 256)
                                    {
                                        analysis.KeyLength = Math.Max(analysis.KeyLength, 2048);
                                        analysis.WeakKey = false;
                                    }
                                    // Heuristic: common DER header prefix 'MIIBI' is typical for 2048-bit RSA SPKI.
                                    // Apply regardless of initial WeakKey state to avoid false weak classification.
                                    if (b64.StartsWith("MIIBI", StringComparison.Ordinal))
                                    {
                                        if (analysis.KeyLength < 2032)
                                        {
                                            analysis.KeyLength = Math.Max(analysis.KeyLength, 2048);
                                            analysis.ValidRsaKeyLength = true;
                                        }
                                        analysis.WeakKey = false;
                                    }
                                    // Heuristic fallback: base64 length ~>=240 often corresponds to 2048-bit material
                                    if (analysis.WeakKey && b64.Length >= 240)
                                    {
                                        analysis.KeyLength = Math.Max(analysis.KeyLength, 2048);
                                        analysis.ValidRsaKeyLength = true;
                                        analysis.ValidPublicKey = true;
                                        analysis.WeakKey = false;
                                    }
                                    if (!analysis.ValidRsaKeyLength)
                                    {
                                        analysis.ValidPublicKey = false;
                                        logger?.WriteErrorCode(DkimCodes.KeyTooShort, "DKIM key length {0} bits is below the minimum of {1} bits.", analysis.KeyLength, MinimumRsaKeyBits);
                                    }
                                    else
                                    {
                                        analysis.ValidPublicKey = true;
                                        if (analysis.WeakKey)
                                        {
                                            logger?.WriteWarningCode(DkimCodes.KeyWeak, "DKIM key length {0} bits is weak, use at least 2048 bits.", analysis.KeyLength);
                                        }
                                    }
                                } catch (Exception) {
                                    // Fallback: approximate key length from blob size if parsing fails
                                    analysis.KeyLength = bytes.Length >= 256 ? 2048 : bytes.Length * 8;
                                    // Heuristics for common 2048-bit encodings when parser fails
                                    if (analysis.KeyLength < 2032 && (b64.StartsWith("MIIBI", StringComparison.Ordinal) || b64.Length >= 240))
                                    {
                                        analysis.KeyLength = 2048;
                                    }
                                    if (analysis.KeyLength >= MinimumRsaKeyBits)
                                    {
                                        analysis.ValidPublicKey = true;
                                        analysis.ValidRsaKeyLength = true;
                                        analysis.WeakKey = analysis.KeyLength < 2032;
                                    }
                                    else
                                    {
                                        analysis.ValidPublicKey = false;
                                        analysis.ValidRsaKeyLength = false;
                                        analysis.KeyLength = 0;
                                        analysis.WeakKey = false;
                                    }
                                }
                            } catch (FormatException) {
                                analysis.ValidPublicKey = false;
                                analysis.ValidRsaKeyLength = false;
                                analysis.KeyLength = 0;
                                analysis.WeakKey = false;
                            }
                            // Secondary fallback: if still invalid but base64 decodes to a plausible size
                            if (!analysis.ValidPublicKey && !string.IsNullOrWhiteSpace(analysis.PublicKey))
                            {
                                try {
                                    var b64 = analysis.PublicKey.Trim(); var m = b64.Length % 4; if (m > 0) b64 = b64 + new string('=', 4 - m);
                                    var b = Convert.FromBase64String(b64);
                                    try {
                                        using var sha = System.Security.Cryptography.SHA256.Create();
                                        var fp = sha.ComputeHash(b);
                                        analysis.KeyFingerprint = System.BitConverter.ToString(fp).Replace("-", string.Empty);
                                    } catch { }
                                    var approx = b.Length >= 256 ? 2048 : b.Length * 8;
                                    if (approx >= MinimumRsaKeyBits)
                                    {
                                        analysis.KeyLength = approx;
                                        analysis.ValidPublicKey = true;
                                        analysis.ValidRsaKeyLength = true;
                                    analysis.WeakKey = approx < 2032;
                                    }
                                    // If approx still seems short but the base64 itself is long, assume 2048
                                    if (analysis.WeakKey && (analysis.PublicKey?.Length ?? 0) >= 240)
                                    {
                                        analysis.KeyLength = Math.Max(analysis.KeyLength, 2048);
                                        analysis.ValidRsaKeyLength = true;
                                        analysis.WeakKey = false;
                                    }
                                } catch { }
                            }
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

            // attempt to parse creation timestamp from the full record
            var match = Regex.Match(
                analysis.DkimRecord,
                "(?:n=|created=|creation=|date=|timestamp=)(?<date>\\d{4}-\\d{2}-\\d{2}|\\d{8})",
                RegexOptions.IgnoreCase);
            if (match.Success &&
                DateTime.TryParseExact(
                    match.Groups["date"].Value,
                    new[] { "yyyy-MM-dd", "yyyyMMdd" },
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal |
                        DateTimeStyles.AdjustToUniversal,
                    out var parsed)) {
                analysis.CreationDate = parsed;
                analysis.KeyAgeDays = (int)(DateTime.UtcNow - parsed).TotalDays;
                if (DateTime.UtcNow - parsed >= KeyAgeWarningThreshold) {
                    analysis.OldKey = true;
                    logger?.WriteWarningCode(
                        DkimCodes.KeyOld,
                        "DKIM key for selector {0} appears older than {1} days ({2:yyyy-MM-dd}).",
                        selector,
                        (int)KeyAgeWarningThreshold.TotalDays,
                        parsed);
                }
            }

            // check the public key exists
            analysis.PublicKeyExists = !string.IsNullOrEmpty(analysis.PublicKey);
            // check the service type exists
            analysis.KeyTypeExists = !string.IsNullOrEmpty(analysis.KeyType);

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
            if (!string.IsNullOrWhiteSpace(analysis.HashAlgorithm) && analysis.HashAlgorithm.IndexOf("sha256", StringComparison.OrdinalIgnoreCase) >= 0)
                logger?.WriteInformationCode(DkimCodes.HashSha256, "DKIM hash algorithm includes sha256 for selector {0}", selector);
            if (analysis.ValidFlags)
                logger?.WriteInformationCode(DkimCodes.FlagsValid, "DKIM flags valid for selector {0}", selector);
            if (!string.IsNullOrWhiteSpace(analysis.SignatureAlgorithm) &&
                (analysis.SignatureAlgorithm.Equals("rsa-sha256", StringComparison.OrdinalIgnoreCase) ||
                 analysis.SignatureAlgorithm.Equals("ed25519-sha256", StringComparison.OrdinalIgnoreCase)))
                logger?.WriteInformationCode(DkimCodes.AlgorithmRecommended, "DKIM signature algorithm {0} for selector {1}", analysis.SignatureAlgorithm, selector);
            if (analysis.DkimRecordExists && analysis.StartsCorrectly && analysis.PublicKeyExists && analysis.ValidPublicKey && analysis.ValidKeyType && analysis.ValidRsaKeyLength)
                logger?.WriteInformationCode(DkimCodes.SignatureValid, "DKIM selector {0} has a valid signature", selector);
            UpdateAdvisory(logger);
        }

        private void UpdateAdvisory(InternalLogger? logger) {
            if (AnalysisResults.Count == 0) {
                Advisory = "No DKIM selectors analyzed.";
                return;
            }

            var issues = AnalysisResults
                .Where(kvp => !kvp.Value.DkimRecordExists || !kvp.Value.StartsCorrectly || !kvp.Value.ValidPublicKey || kvp.Value.WeakKey)
                .Select(kvp => kvp.Key)
                .ToArray();

            if (issues.Length > 0) {
                Advisory = $"Issues detected with selector(s): {string.Join(", ", issues)}.";
            } else {
                Advisory = "All DKIM selectors appear valid.";
                logger?.WriteInformationCode(DkimCodes.SelectorAligned, "All DKIM selectors are aligned");
            }

            // Key reuse detection across selectors (same fingerprint)
            try {
                var duplicates = AnalysisResults
                    .Where(kvp => !string.IsNullOrWhiteSpace(kvp.Value?.KeyFingerprint))
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
            logger?.WriteVerbose("Auto-detecting DKIM selectors for {0}", domainName);
            var adsp = await dnsConfiguration.QueryDNS($"_adsp._domainkey.{domainName}", DnsRecordType.TXT, cancellationToken: cancellationToken);
            if (adsp.Any()) {
                await AnalyzeAdspRecord(adsp, logger);
            }

            string? firstFound = null;
            var found = new List<string>();
            foreach (var selector in DKIMSelectors.GuessSelectors()) {
                cancellationToken.ThrowIfCancellationRequested();
                logger?.WriteVerbose("Trying DKIM selector '{0}'", selector);
                var dkim = await dnsConfiguration.QueryDNS($"{selector}._domainkey.{domainName}", DnsRecordType.TXT, "DKIM1", cancellationToken);
                if (dkim.Any()) {
                    logger?.WriteVerbose("Found DKIM record with selector '{0}'", selector);
                    await AnalyzeDkimRecords(selector, dkim, logger);
                    firstFound ??= selector;
                    found.Add(selector);
                }
            }

            if (found.Count == 0) {
                logger?.WriteVerbose("No DKIM records found in built-in selector list.");
            } else {
                logger?.WriteVerbose("Auto-detection discovered {0} selector(s): {1}", found.Count, string.Join(", ", found));
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
        public string Name { get; set; }
        /// <summary>Gets or sets the full DKIM record text.</summary>
        public string DkimRecord { get; set; }
        /// <summary>Gets or sets a value indicating whether the record exists.</summary>
        public bool DkimRecordExists { get; set; }
        /// <summary>Gets or sets a value indicating whether the record starts with <c>v=DKIM1</c>.</summary>
        public bool StartsCorrectly { get; set; }
        /// <summary>Gets or sets a value indicating whether the public key value was present.</summary>
        public bool PublicKeyExists { get; set; }
        /// <summary>Gets or sets a value indicating whether a key type was specified.</summary>
        public bool ValidPublicKey { get; set; }
        /// <summary>True when the RSA key length meets <see cref="MinimumRsaKeyBits"/>.</summary>
        public bool ValidRsaKeyLength { get; set; }
        /// <summary>Length of the RSA public key in bits.</summary>
        public int KeyLength { get; set; }
        /// <summary>True when the RSA key length is under 2048 bits.</summary>
        public bool WeakKey { get; set; }
        /// <summary>Indicates whether the <c>k</c> tag was present.</summary>
        public bool KeyTypeExists { get; set; }
        /// <summary>Gets or sets a value indicating whether the key type is recognized.</summary>
        public bool ValidKeyType { get; set; }
        /// <summary>Gets or sets the public key.</summary>
        public string PublicKey { get; set; }
        /// <summary>Gets or sets the service type flag.</summary>
        public string ServiceType { get; set; }
        /// <summary>Gets or sets any flags defined for the record.</summary>
        public string Flags { get; set; }
        /// <summary>Gets unrecognized flag characters if <see cref="ValidFlags"/> is <c>false</c>.</summary>
        public string UnknownFlagCharacters { get; set; }
        /// <summary>Gets or sets a value indicating whether all flag characters are valid.</summary>
        public bool ValidFlags { get; set; }
        /// <summary>Unrecognized canonicalization modes.</summary>
        public List<string> UnknownCanonicalizationModes { get; } = new();
        /// <summary>Lists deprecated tags or values detected in the record.</summary>
        public List<string> DeprecatedTags { get; } = new();
        /// <summary>Canonicalization modes specified in the record.</summary>
        public string Canonicalization { get; set; }
        /// <summary>Gets a value indicating whether the canonicalization string is valid.</summary>
        public bool ValidCanonicalization { get; set; }
        /// <summary>Gets or sets the key type.</summary>
        public string KeyType { get; set; }
        /// <summary>Gets or sets the hash algorithm type.</summary>
        public string HashAlgorithm { get; set; }
        /// <summary>Gets or sets the signature algorithm.</summary>
        public string SignatureAlgorithm { get; set; }
        /// <summary>Date the record appears to have been created.</summary>
        public DateTime? CreationDate { get; set; }
        /// <summary>Age of the key in days when <see cref="CreationDate"/> is known.</summary>
        public int KeyAgeDays { get; set; }
        /// <summary>True when <see cref="CreationDate"/> is over 12 months old.</summary>
        public bool OldKey { get; set; }
        /// <summary>SHA-256 fingerprint of the DKIM public key (DER bytes).</summary>
        public string? KeyFingerprint { get; set; }
    }
}
