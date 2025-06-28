using DnsClientX;
using DomainDetective.Definitions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DomainDetective {
    public class DkimAnalysis {
        /// <summary>Minimum allowed RSA key size in bits.</summary>
        public const int MinimumRsaKeyBits = 1024;
        /// <summary>Gets the analysis results keyed by selector.</summary>
        public Dictionary<string, DkimRecordAnalysis> AnalysisResults { get; private set; } = new Dictionary<string, DkimRecordAnalysis>();

        /// <summary>Clears <see cref="AnalysisResults"/>.</summary>
        public void Reset() {
            AnalysisResults = new Dictionary<string, DkimRecordAnalysis>();
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
                                analysis.ValidPublicKey = analysis.ValidRsaKeyLength;
                                } catch (Exception) {
                                    analysis.ValidPublicKey = false;
                                    analysis.ValidRsaKeyLength = false;
                                analysis.KeyLength = 0;
                                }
                            } catch (FormatException) {
                                analysis.ValidPublicKey = false;
                                analysis.ValidRsaKeyLength = false;
                                analysis.KeyLength = 0;
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
                        case "h":
                            analysis.HashAlgorithm = value;
                            break;
                    }
                }
            }

            // check the public key exists
            analysis.PublicKeyExists = !string.IsNullOrEmpty(analysis.PublicKey);
            // check the service type exists
            analysis.KeyTypeExists = !string.IsNullOrEmpty(analysis.KeyType);

            AnalysisResults[selector] = analysis;
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
        /// <summary>Gets or sets the key type.</summary>
        public string KeyType { get; set; }
        /// <summary>Gets or sets the hash algorithm type.</summary>
        public string HashAlgorithm { get; set; }
    }
}