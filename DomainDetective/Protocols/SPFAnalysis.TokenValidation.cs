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
        private void UpdateAdvisory(InternalLogger? logger) {
            if (!SpfRecordExists) {
                Advisory = "No SPF record found.";
                logger?.WriteWarningCode(SpfCodes.MissingRecord, Advisory);
                return;
            }
            if (MultipleSpfRecords) {
                Advisory = "Multiple SPF records published.";
                logger?.WriteWarningCode(SpfCodes.MultipleRecords, Advisory);
                return;
            }
            if (!StartsCorrectly) {
                Advisory = "SPF record does not start with v=spf1.";
                logger?.WriteWarningCode(SpfCodes.StartsInvalid, Advisory);
                return;
            }
            if (ExceedsDnsLookups) {
                Advisory = "SPF record exceeds DNS lookup limit.";
                logger?.WriteWarningCode(SpfCodes.LookupsExceeded, Advisory);
                return;
            }

            Advisory = "SPF record passed basic checks.";
            logger?.WriteInformationCode(SpfCodes.Present, "SPF record present");
            logger?.WriteInformationCode(SpfCodes.StartsV1, "SPF starts with v=spf1");
            if (AllMechanism?.Equals("-all", StringComparison.OrdinalIgnoreCase) == true)
                logger?.WriteInformationCode(SpfCodes.AllEnforced, "SPF ends with -all (enforced)");
            if (!ExceedsDnsLookups)
                logger?.WriteInformationCode(SpfCodes.LookupsWithinLimit, $"DNS lookups within limit: {DnsLookupsCount}/10");
            if (DnsLookups.Count > 0 && !CycleDetected)
                logger?.WriteInformationCode(SpfCodes.IncludeChainValid, "SPF include/redirect chain resolves without loops");
        }


        private async Task<int> CountDnsLookups(string[] parts, HashSet<string> visitedDomains, List<string> path, InternalLogger? logger) {
            int dnsLookups = 0;
            foreach (var part in parts) {
                var token = part.Trim('"').Trim();
                if (token.Length > 0 && "+-~?".IndexOf(token[0]) >= 0) {
                    token = token.Substring(1);
                }

                if (token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                    dnsLookups++;
                    var domain = token.Substring("include:".Length);
                    if (domain != string.Empty) {
                        if (!visitedDomains.Add(domain)) {
                            CycleDetected = true;
                            CyclePath ??= string.Join(" -> ", path.Concat(new[] { domain }));
                            PermError = true;
                            return dnsLookups;
                        }

                        DnsLookups.Add(domain);
                        path.Add(domain);
                        var record = await ResolveSpfRecordForCounting(domain, logger, "include");
                        if (!string.IsNullOrWhiteSpace(record)) {
                            var resultParts = TokenizeSpfRecord(record!).ToArray();
                            foreach (var rp in resultParts) {
                                AddPartToResolvedLists(rp, logger, domain, path.Count, path);
                            }
                            dnsLookups += await CountDnsLookups(resultParts, visitedDomains, path, logger);
                        }
                        path.RemoveAt(path.Count - 1);
                        visitedDomains.Remove(domain);
                    }
                } else if (token.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)) {
                    dnsLookups++;
                    var domain = token.Substring("redirect=".Length);
                    if (domain != string.Empty) {
                        RedirectVisitedDomains.Add(domain);
                        if (!visitedDomains.Add(domain)) {
                            CycleDetected = true;
                            CyclePath ??= string.Join(" -> ", path.Concat(new[] { domain }));
                            PermError = true;
                            return dnsLookups;
                        }

                        DnsLookups.Add(domain);
                        path.Add(domain);
                        var record = await ResolveSpfRecordForCounting(domain, logger, "redirect");
                        if (!string.IsNullOrWhiteSpace(record)) {
                            var resultParts = TokenizeSpfRecord(record!).ToArray();
                            foreach (var rp in resultParts) {
                                AddPartToResolvedLists(rp, logger, domain, path.Count, path);
                            }
                            dnsLookups += await CountDnsLookups(resultParts, visitedDomains, path, logger);
                        }
                        path.RemoveAt(path.Count - 1);
                        visitedDomains.Remove(domain);
                    }
                } else if (token.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) {
                    var domain = token.Substring("exists:".Length);
                    if (domain != string.Empty) {
                        DnsLookups.Add(domain);
                    }
                    dnsLookups++;
                } else if (IsDnsLookupMechanism(token)) {
                    var domain = ExtractMechanismDomain(token);
                    if (domain != string.Empty) {
                        DnsLookups.Add(domain);
                    }
                    dnsLookups++;
                }
            }
            return dnsLookups;
        }

        private async Task<string?> ResolveSpfRecordForCounting(string domain, InternalLogger? logger, string mechanism) {
            if (TestSpfRecords.TryGetValue(domain, out var testRecord)) {
                return testRecord;
            }

            try {
                var answers = await DnsConfiguration.QueryDNS(
                    domain,
                    DnsRecordType.TXT,
                    "SPF1",
                    includeAliasesInFilter: true);
                var records = answers
                    .Where(answer => answer.Type == DnsRecordType.TXT)
                    .Select(answer => answer.TxtConcatenatedData)
                    .Where(IsSpfPolicyRecord)
                    .ToArray();
                if (records.Length > 1) {
                    PermError = true;
                    logger?.WriteWarningCode(SpfCodes.MultipleRecords, "Multiple SPF records found while resolving {0} target {1}.", mechanism, domain);
                    return null;
                }
                return records.FirstOrDefault();
            } catch (Exception ex) when (ex is TaskCanceledException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException) {
                logger?.WriteWarningCode(SpfCodes.QueryFailed, "SPF {0} lookup failed for {1}: {2}", mechanism, domain, ex.Message);
                return null;
            }
        }

        private static bool IsDnsLookupMechanism(string token) {
            return token.Equals("a", StringComparison.OrdinalIgnoreCase) ||
                   token.StartsWith("a:", StringComparison.OrdinalIgnoreCase) ||
                   token.StartsWith("a/", StringComparison.OrdinalIgnoreCase) ||
                   token.Equals("mx", StringComparison.OrdinalIgnoreCase) ||
                   token.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) ||
                   token.StartsWith("mx/", StringComparison.OrdinalIgnoreCase) ||
                   token.Equals("ptr", StringComparison.OrdinalIgnoreCase) ||
                   token.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase);
        }

        private static string ExtractMechanismDomain(string token) {
            var colon = token.IndexOf(':');
            if (colon < 0 || colon == token.Length - 1) {
                return string.Empty;
            }
            var domain = token.Substring(colon + 1);
            var slash = domain.IndexOf('/');
            return slash >= 0 ? domain.Substring(0, slash) : domain;
        }

        private int CountAllMechanisms(string[] parts) {
            return parts.Count(part => IsAllMechanism(part));
        }

        private void CheckForNullDnsLookups(string[] parts) {
            foreach (var part in parts) {
                if ((part.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("include:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("exists:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) && part.EndsWith(":", StringComparison.Ordinal)) {
                    HasNullLookups = true;
                }
            }
        }

        private void CheckCharacterLimits(IEnumerable<DnsAnswer> spfRecords) {
            int totalLength = 0;
            foreach (var record in spfRecords) {
                foreach (var chunk in record.DataStringsEscaped) {
                    var sanitized = TrimQuotes(chunk);
                    totalLength += sanitized.Length;
                    ExceedsCharacterLimit = ExceedsCharacterLimit || sanitized.Length > 255;
                }
            }
            ExceedsTotalCharacterLimit = totalLength > 512;
        }

        /// <summary>Adds warnings for SPF TXT chunks over 255 characters.</summary>
        private void WarnIfSpfRecordChunksTooLong(InternalLogger? logger) {
            for (int i = 0; i < SpfRecords.Count; i++) {
                if (SpfRecords[i].Length > 255) {
                    _warnings.Add($"SPF record chunk {i + 1} exceeds 255 characters.");
                    logger?.WriteWarningCode(SpfCodes.TxtChunkTooLong, $"SPF record chunk {i + 1} exceeds 255 characters.");
                }
            }
        }

        private void WarnIfExceedsDnsLookups(InternalLogger? logger) {
            if (ExceedsDnsLookups) {
                var message = $"SPF record requires {DnsLookupsCount} DNS lookups which exceeds the limit of {MaxDnsLookups}.";
                if (!_warnings.Contains(message)) {
                    _warnings.Add(message);
                }
                logger?.WriteWarningCode(SpfCodes.LookupsExceeded, message);
            }
        }

        private static string TrimQuotes(string value) {
            var trimmed = value.Trim();
            if (trimmed.Length == 0) {
                return trimmed;
            }

            if (trimmed.StartsWith("\\\"", StringComparison.Ordinal)) {
                trimmed = trimmed.Substring(2);
            } else if (trimmed.StartsWith("\"", StringComparison.Ordinal)) {
                trimmed = trimmed.Substring(1);
            }

            if (trimmed.EndsWith("\\\"", StringComparison.Ordinal)) {
                trimmed = trimmed.Substring(0, trimmed.Length - 2);
            } else if (trimmed.EndsWith("\"", StringComparison.Ordinal)) {
                trimmed = trimmed.Substring(0, trimmed.Length - 1);
            }

            return trimmed;
        }

        private void AddPartToList(string part, InternalLogger? logger, string? sourceDomain, int depth, IEnumerable<string>? chain) {
            var token = part.Trim('"');
            var normalized = token.TrimStart('+', '-', '~', '?');
            ValidateMacros(token, logger);
            // Create a mechanism breakdown entry for provenance at any depth
            var mech = BuildPart(token, sourceDomain, depth, chain);
            if (mech != null) {
                SpfPartAnalyses.Add(mech);
            }
            // Only mutate top-level collections for the subject domain (depth == 0)
            var isTopLevel = depth == 0 && (string.IsNullOrEmpty(sourceDomain) || string.Equals(sourceDomain, Subject, StringComparison.OrdinalIgnoreCase));
            if (isTopLevel) {
                if (normalized.Equals("a", StringComparison.OrdinalIgnoreCase)) {
                    ARecords.Add(string.Empty);
                } else if (normalized.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || normalized.StartsWith("a/", StringComparison.OrdinalIgnoreCase)) {
                    ARecords.Add(normalized.Substring(1).TrimStart(':').Trim('"'));
                } else if (normalized.Equals("mx", StringComparison.OrdinalIgnoreCase)) {
                    MxRecords.Add(string.Empty);
                } else if (normalized.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || normalized.StartsWith("mx/", StringComparison.OrdinalIgnoreCase)) {
                    MxRecords.Add(normalized.Substring(2).TrimStart(':').Trim('"'));
                } else if (normalized.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)) {
                    PtrRecords.Add(normalized.Substring(4).Trim('"'));
                } else if (normalized.Equals("ptr", StringComparison.OrdinalIgnoreCase)) {
                    PtrRecords.Add(string.Empty);
                } else if (normalized.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) {
                    ExistsRecords.Add(normalized.Substring(7).Trim('"'));
                } else if (normalized.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)) {
                    var value = normalized.Substring(4).Trim('"');
                    Ipv4Records.Add(value);
                    if (!TryParseCidr(value, 32)) {
                        InvalidIpSyntax = true;
                    }
                } else if (normalized.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) {
                    var value = normalized.Substring(4).Trim('"');
                    Ipv6Records.Add(value);
                    if (!TryParseCidr(value, 128)) {
                        InvalidIpSyntax = true;
                    }
                } else if (normalized.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                    IncludeRecords.Add(normalized.Substring(8).Trim('"'));
                } else if (normalized.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)) {
                    RedirectValue = normalized.Substring(9).Trim('"');
                    HasRedirect = true;
                } else if (normalized.StartsWith("exp=", StringComparison.OrdinalIgnoreCase)) {
                    ExpValue = normalized.Substring(4).Trim('"');
                    HasExp = true;
                } else if (IsAllMechanism(token)) {
                    AllMechanism = token.Trim('"');
                } else if (!IsAllowedMechanismOrModifier(normalized)) {
                    if (!UnknownMechanisms.Contains(token)) {
                        UnknownMechanisms.Add(token);
                    }
                }
            } else {
                // Non-top-level: keep Unknowns through resolved path so they can be surfaced once
                if (!IsAllowedMechanismOrModifier(normalized) && !IsAllMechanism(normalized)) {
                    if (!UnknownMechanisms.Contains(token)) {
                        UnknownMechanisms.Add(token);
                    }
                }
            }

            AddPartToResolvedLists(part, logger, sourceDomain, depth, chain);
        }

        private void AddPartToResolvedLists(string part, InternalLogger? logger, string? sourceDomain, int depth, IEnumerable<string>? chain) {
            var token = part.Trim('"');
            var normalized = token.TrimStart('+', '-', '~', '?');
            // also ensure mechanism list contains parts encountered through includes/redirects
            var mech = BuildPart(token, sourceDomain, depth, chain);
            if (mech != null) {
                SpfPartAnalyses.Add(mech);
            }
            if (normalized.Equals("a", StringComparison.OrdinalIgnoreCase)) {
                ResolvedARecords.Add(string.Empty);
            } else if (normalized.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || normalized.StartsWith("a/", StringComparison.OrdinalIgnoreCase)) {
                ResolvedARecords.Add(normalized.Substring(1).TrimStart(':').Trim('"'));
            } else if (normalized.Equals("mx", StringComparison.OrdinalIgnoreCase)) {
                ResolvedMxRecords.Add(string.Empty);
            } else if (normalized.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || normalized.StartsWith("mx/", StringComparison.OrdinalIgnoreCase)) {
                ResolvedMxRecords.Add(normalized.Substring(2).TrimStart(':').Trim('"'));
            } else if (normalized.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedPtrRecords.Add(normalized.Substring(4).Trim('"'));
            } else if (normalized.Equals("ptr", StringComparison.OrdinalIgnoreCase)) {
                ResolvedPtrRecords.Add(string.Empty);
            } else if (normalized.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedExistsRecords.Add(normalized.Substring(7).Trim('"'));
            } else if (normalized.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedIpv4Records.Add(normalized.Substring(4).Trim('"'));
            } else if (normalized.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedIpv6Records.Add(normalized.Substring(4).Trim('"'));
            } else if (normalized.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedIncludeRecords.Add(normalized.Substring(8).Trim('"'));
            } else if (!IsAllowedMechanismOrModifier(normalized) && !IsAllMechanism(normalized)) {
                if (!UnknownMechanisms.Contains(token)) {
                    UnknownMechanisms.Add(token);
                }
            }
            ValidateMacros(token, logger);
        }

        private static readonly (string suffix, string provider)[] _providerSuffixes = new (string, string)[] {
            ("_spf.google.com", "Google Workspace"),
            ("spf.protection.outlook.com", "Microsoft 365"),
            ("outlook.com", "Microsoft 365"),
            ("_spf.salesforce.com", "Salesforce"),
            ("_spf.mailgun.org", "Mailgun"),
            ("mailgun.org", "Mailgun"),
            ("_spf.sendgrid.net", "SendGrid"),
            ("sendgrid.net", "SendGrid"),
            ("spf.mandrillapp.com", "Mailchimp/Mandrill"),
            ("spf.sparkpostmail.com", "SparkPost"),
            ("spf.emailsrvr.com", "Rackspace Email"),
            ("_spf.zoho.com", "Zoho Mail"),
            ("_spf.yandex.net", "Yandex"),
            ("_spf.elasticemail.com", "Elastic Email"),
            ("spf.mailjet.com", "Mailjet"),
            ("_spf.constantcontact.com", "Constant Contact"),
            ("_spf.mimecast.com", "Mimecast"),
        };

        private static string? ProviderForDomain(string? domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return null;
            var d = domain!.Trim('.');
            foreach (var (suffix, provider) in _providerSuffixes)
            {
                if (DomainHelper.IsDomainOrSubdomainOf(d, suffix))
                {
                    return provider;
                }
            }
            return null;
        }

        private static SpfPartAnalysis? BuildPart(string token, string? sourceDomain = null, int depth = 0, IEnumerable<string>? chain = null)
        {
            if (string.IsNullOrWhiteSpace(token)) return null;
            // Qualifier
            var qualifier = token[0] is '+' or '-' or '~' or '?' ? token[0].ToString() : string.Empty;
            var trimmed = token.TrimStart('+', '-', '~', '?');
            string type;
            string value = string.Empty;
            if (trimmed.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
            {
                type = "redirect"; value = trimmed.Substring(9);
            }
            else if (trimmed.StartsWith("exp=", StringComparison.OrdinalIgnoreCase))
            {
                type = "exp"; value = trimmed.Substring(4);
            }
            else if (trimmed.StartsWith("include:", StringComparison.OrdinalIgnoreCase))
            {
                type = "include"; value = trimmed.Substring(8);
            }
            else if (trimmed.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase))
            {
                type = "ip4"; value = trimmed.Substring(4);
            }
            else if (trimmed.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase))
            {
                type = "ip6"; value = trimmed.Substring(4);
            }
            else if (trimmed.Equals("a", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("a/", StringComparison.OrdinalIgnoreCase))
            {
                type = "a"; value = trimmed.Length > 2 ? trimmed.Substring(2) : string.Empty;
            }
            else if (trimmed.Equals("mx", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("mx/", StringComparison.OrdinalIgnoreCase))
            {
                type = "mx"; value = trimmed.Length > 3 ? trimmed.Substring(3) : string.Empty;
            }
            else if (trimmed.StartsWith("exists:", StringComparison.OrdinalIgnoreCase))
            {
                type = "exists"; value = trimmed.Substring(7);
            }
            else if (trimmed.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase) || trimmed.Equals("ptr", StringComparison.OrdinalIgnoreCase))
            {
                type = "ptr"; value = trimmed.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase) ? trimmed.Substring(4) : string.Empty;
            }
            else if (IsAllMechanism(trimmed))
            {
                type = "all"; value = trimmed;
            }
            else if (trimmed.Equals("v=spf1", StringComparison.OrdinalIgnoreCase))
            {
                type = "version"; value = "v=spf1";
            }
            else
            {
                // Unknown or non-standard, ignore
                return null;
            }

            var pa = new SpfPartAnalysis {
                Prefix = qualifier,
                Type = type,
                Value = value,
                PrefixDesc = qualifier switch { 
                    "+" => "pass",
                    "-" => "fail",
                    "~" => "softfail",
                    "?" => "neutral",
                    _ => string.Empty },
                Description = type,
                SourceDomain = sourceDomain,
                Depth = depth,
                Chain = chain?.ToList() ?? new List<string>()
            };
            // Provider annotation for domain-bearing parts
            if (type is "include" or "a" or "mx" or "exists" or "ptr" or "redirect")
            {
                var prov = ProviderForDomain(value);
                if (!string.IsNullOrEmpty(prov)) pa.Provider = prov;
            }
            return pa;
        }

        /// <summary>
        /// Validates SPF macro syntax within a token and records warnings.
        /// </summary>
        /// <param name="token">SPF token that may contain macros.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        private void ValidateMacros(string token, InternalLogger? logger) {
            var index = token.IndexOf('%');
            while (index >= 0 && index < token.Length) {
                if (index + 1 >= token.Length) {
                    _warnings.Add($"Invalid percent escape in token '{token}'");
                    logger?.WriteWarningCode(SpfCodes.MacroPercentInvalid, $"Invalid percent escape in token '{token}'");
                    break;
                }

                var next = token[index + 1];
                if (next == '%') {
                    index = token.IndexOf('%', index + 2);
                    continue;
                }

                if (next == '_' || next == '-') {
                    index = token.IndexOf('%', index + 2);
                    continue;
                }

                if (next == '{') {
                    var end = token.IndexOf('}', index + 2);
                    if (end == -1) {
                        _warnings.Add($"Invalid SPF macro syntax in token '{token}'");
                        logger?.WriteWarningCode(SpfCodes.MacroSyntaxInvalid, $"Invalid SPF macro syntax in token '{token}'");
                        break;
                    }

                    var macro = token.Substring(index, end - index + 1);
                    if (!IsValidMacro(macro)) {
                        _warnings.Add($"Invalid SPF macro syntax: {macro}");
                        logger?.WriteWarningCode(SpfCodes.MacroSyntaxInvalid, $"Invalid SPF macro syntax: {macro}");
                    }
                    index = token.IndexOf('%', end + 1);
                    continue;
                }

                _warnings.Add($"Invalid percent escape in token '{token}'");
                logger?.WriteWarningCode(SpfCodes.MacroPercentInvalid, $"Invalid percent escape in token '{token}'");
                index = token.IndexOf('%', index + 1);
            }
        }

        private static bool IsValidMacro(string macro) {
            var match = MacroRegex.Match(macro);
            if (!match.Success) {
                return false;
            }

            if (match.Groups["digits"].Success &&
                (!int.TryParse(match.Groups["digits"].Value, out var digits) || digits > 99)) {
                return false;
            }

            return true;
        }

        private static bool IsAllowedMechanismOrModifier(string token) {
            return token.Equals("a", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("a:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("a/", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("mx:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("mx/", StringComparison.OrdinalIgnoreCase)
                   || token.Equals("mx", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)
                   || token.Equals("ptr", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("exp=", StringComparison.OrdinalIgnoreCase)
                   || token.Equals("v=spf1", StringComparison.OrdinalIgnoreCase)
                   || IsAllMechanism(token);
        }
      
        private static bool TryParseCidr(string value, int maxPrefixLength) {
            var segments = value.Split(new[] { '/' }, StringSplitOptions.None);
            if (segments.Length == 0 || segments.Length > 2) {
                return false;
            }

            if (!IPAddress.TryParse(segments[0], out _)) {
                return false;
            }

            if (segments.Length == 2) {
                if (segments[1].Length == 0) {
                    return false;
                }
                if (!int.TryParse(segments[1], NumberStyles.None, CultureInfo.InvariantCulture, out var mask)) {
                    return false;
                }

                if (mask < 0 || mask > maxPrefixLength) {
                    return false;
                }
            }

            return true;
        }

        private static bool IsAllMechanism(string part) {
            return part.Equals("all", StringComparison.OrdinalIgnoreCase)
                   || part.Equals("+all", StringComparison.OrdinalIgnoreCase)
                   || part.Equals("~all", StringComparison.OrdinalIgnoreCase)
                   || part.Equals("?all", StringComparison.OrdinalIgnoreCase)
                   || part.Equals("-all", StringComparison.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> TokenizeSpfRecord(string record) {
            var tokens = new List<string>();
            if (string.IsNullOrEmpty(record)) {
                return tokens;
            }

            var current = new System.Text.StringBuilder();
            var inQuotes = false;
            var escapeNext = false;
            var commentDepth = 0;

            foreach (var c in record) {
                if (escapeNext) {
                    if (commentDepth == 0) {
                        current.Append(c);
                    }
                    escapeNext = false;
                    continue;
                }

                if (c == '\\') {
                    escapeNext = true;
                    continue;
                }

                if (commentDepth > 0) {
                    if (c == '(') {
                        commentDepth++;
                    } else if (c == ')') {
                        commentDepth--;
                    }
                    continue;
                }

                if (!inQuotes && c == '(') {
                    commentDepth = 1;
                    continue;
                }

                if (c == '"') {
                    if (inQuotes) {
                        // Closing quote: finalize token (may include a prefix like include:)
                        tokens.Add(current.ToString());
                        current.Clear();
                        inQuotes = false;
                    } else {
                        // Opening quote: if buffer ends with a known prefix (include:, redirect=, exp=),
                        // keep it to create a single token such as include:example.com
                        var prefix = current.ToString();
                        if (!(prefix.EndsWith("include:", StringComparison.OrdinalIgnoreCase)
                              || prefix.EndsWith("redirect=", StringComparison.OrdinalIgnoreCase)
                              || prefix.EndsWith("exp=", StringComparison.OrdinalIgnoreCase))) {
                            if (current.Length > 0) {
                                tokens.Add(current.ToString());
                                current.Clear();
                            }
                        }
                        inQuotes = true;
                    }
                } else if (char.IsWhiteSpace(c) && !inQuotes) {
                    if (current.Length > 0) {
                        tokens.Add(current.ToString());
                        current.Clear();
                    }
                } else {
                    current.Append(c);
                }
            }

            if (current.Length > 0) {
                tokens.Add(current.ToString());
            }

            return tokens;
        }

    }
}
