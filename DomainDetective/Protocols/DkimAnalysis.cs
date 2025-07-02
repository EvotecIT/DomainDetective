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
    public class DkimAnalysis {
        /// <summary>Minimum allowed RSA key size in bits.</summary>
        public const int MinimumRsaKeyBits = 1024;
        /// <summary>Gets the analysis results keyed by selector.</summary>
        public Dictionary<string, DkimRecordAnalysis> AnalysisResults { get; private set; } = new Dictionary<string, DkimRecordAnalysis>();
        /// <summary>Gets the ADSP record text when present.</summary>
        public string? AdspRecord { get; private set; }
        /// <summary>Gets a value indicating whether an ADSP record exists.</summary>
        public bool AdspRecordExists { get; private set; }

        /// <summary>Clears <see cref="AnalysisResults"/>.</summary>
        public void Reset() {
            AnalysisResults = new Dictionary<string, DkimRecordAnalysis>();
            AdspRecord = null;
            AdspRecordExists = false;
        }

        /// <summary>
        /// Analyses DKIM TXT records for the specified selector.
        /// </summary>
        /// <param name="selector">DKIM selector being processed.</param>
        /// <param name="dnsResults">TXT records from the DNS query.</param>
        /// <param name="logger">Logger used for verbose output.</param>
        public async Task AnalyzeDkimRecords(string selector, IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
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
                analysis.Name = record.Name;
                if (record.DataStringsEscaped != null && record.DataStringsEscaped.Length > 0) {
                    analysis.DkimRecord += string.Join(string.Empty, record.DataStringsEscaped);
                } else {
                    analysis.DkimRecord += record.Data;
                }
            }

            logger.WriteVerbose($"Analyzing DKIM record {analysis.DkimRecord}");

            if (analysis.DkimRecord == null) {
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
                                var bytes = Convert.FromBase64String(value);
                                try {
                                var rsaKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(bytes);
                                analysis.KeyLength = rsaKey.Modulus.BitLength;
                                analysis.ValidRsaKeyLength = analysis.KeyLength >= MinimumRsaKeyBits;
                                analysis.WeakKey = analysis.KeyLength > 0 && analysis.KeyLength < 2048;
                                analysis.ValidPublicKey = analysis.ValidRsaKeyLength;
                                if (analysis.WeakKey)
                                {
                                    logger?.WriteWarning("DKIM key length {0} bits is weak, use at least 2048 bits.", analysis.KeyLength);
                                }
                                } catch (Exception) {
                                    analysis.ValidPublicKey = false;
                                    analysis.ValidRsaKeyLength = false;
                                    analysis.KeyLength = 0;
                                    analysis.WeakKey = false;
                                }
                            } catch (FormatException) {
                                analysis.ValidPublicKey = false;
                                analysis.ValidRsaKeyLength = false;
                                analysis.KeyLength = 0;
                                analysis.WeakKey = false;
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
                                        logger?.WriteError("Unknown canonicalization mode: {0}", part);
                                    }
                                }
                            }
                            break;
                        case "h":
                            analysis.HashAlgorithm = value;
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
                if (DateTime.UtcNow - parsed > TimeSpan.FromDays(365)) {
                    analysis.OldKey = true;
                    logger?.WriteWarning(
                        "DKIM key for selector {0} appears older than 12 months ({1:yyyy-MM-dd}).",
                        selector,
                        parsed);
                }
            }

            // check the public key exists
            analysis.PublicKeyExists = !string.IsNullOrEmpty(analysis.PublicKey);
            // check the service type exists
            analysis.KeyTypeExists = !string.IsNullOrEmpty(analysis.KeyType);

            AnalysisResults[selector] = analysis;
        }

        /// <summary>
        /// Processes ADSP TXT records.
        /// </summary>
        /// <param name="dnsResults">TXT answers from the DNS query.</param>
        /// <param name="logger">Logger used for warnings.</param>
        public async Task AnalyzeAdspRecord(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
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

            AdspRecord = string.Join(" ", records.Select(r => r.Data));
            logger?.WriteWarning("ADSP record found but ADSP is obsolete.");
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
            var adsp = await dnsConfiguration.QueryDNS($"_adsp._domainkey.{domainName}", DnsRecordType.TXT, cancellationToken: cancellationToken);
            if (adsp.Any()) {
                await AnalyzeAdspRecord(adsp, logger);
            }

            foreach (var selector in DKIMSelectors.GuessSelectors()) {
                var dkim = await dnsConfiguration.QueryDNS($"{selector}._domainkey.{domainName}", DnsRecordType.TXT, "DKIM1", cancellationToken);
                if (dkim.Any()) {
                    await AnalyzeDkimRecords(selector, dkim, logger);
                    return selector;
                }
            }

            return null;
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
        /// <summary>Canonicalization modes specified in the record.</summary>
        public string Canonicalization { get; set; }
        /// <summary>Gets a value indicating whether the canonicalization string is valid.</summary>
        public bool ValidCanonicalization { get; set; }
        /// <summary>Gets or sets the key type.</summary>
        public string KeyType { get; set; }
        /// <summary>Gets or sets the hash algorithm type.</summary>
        public string HashAlgorithm { get; set; }
        /// <summary>Date the record appears to have been created.</summary>
        public DateTime? CreationDate { get; set; }
        /// <summary>True when <see cref="CreationDate"/> is over 12 months old.</summary>
        public bool OldKey { get; set; }
    }
}