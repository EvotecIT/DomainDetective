using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class SpfAnalysis {
    /// <summary>
    /// Evaluates an RFC 7208 SPF policy for the specified SMTP identity and address.
    /// </summary>
    /// <param name="domain">Domain whose SPF policy is evaluated.</param>
    /// <param name="ip">Connecting SMTP client address.</param>
    /// <param name="sender">MAIL FROM identity used for macro expansion.</param>
    /// <param name="helo">HELO/EHLO identity used for macro expansion.</param>
    /// <param name="logger">Optional diagnostic logger.</param>
    /// <param name="cancellationToken">Token used to cancel DNS evaluation.</param>
    /// <returns>The RFC 7208 result and the mechanism that determined it.</returns>
    public async Task<SpfHostEvaluation> EvaluateHostAsync(
        string domain,
        IPAddress ip,
        string sender,
        string helo,
        InternalLogger? logger = null,
        CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentException("An SPF domain is required.", nameof(domain));
        }
        if (ip == null) {
            throw new ArgumentNullException(nameof(ip));
        }

        domain = domain.Trim().TrimEnd('.');
        var evaluation = new SpfHostEvaluation {
            Subject = domain,
            IpAddress = ip.ToString(),
            Sender = string.IsNullOrWhiteSpace(sender) ? $"postmaster@{domain}" : sender,
            Helo = string.IsNullOrWhiteSpace(helo) ? $"mail.{domain}" : helo,
            Verdict = "neutral"
        };

        var recursionPath = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var lookups = 0;

        bool ConsumeLookup() {
            lookups++;
            if (lookups <= MaxDnsLookups) {
                return true;
            }
            evaluation.LookupsExceeded = true;
            return false;
        }

        async Task<DnsAnswer[]> QueryAsync(string name, DnsRecordType type) {
            cancellationToken.ThrowIfCancellationRequested();
            if (type == DnsRecordType.TXT && TestSpfRecords.TryGetValue(name, out var testRecord)) {
                return new[] { new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = testRecord } };
            }
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }
            return await DnsConfiguration.QueryDNS(
                name,
                type,
                filter: string.Empty,
                includeAliasesInFilter: true,
                cancellationToken: cancellationToken);
        }

        async Task<(string? Record, bool Multiple, bool Failed)> GetRecordAsync(string name, bool useAnalyzedRecord) {
            if (useAnalyzedRecord && SpfRecordExists) {
                return (SpfRecord, MultipleSpfRecords, false);
            }
            try {
                var answers = await QueryAsync(name, DnsRecordType.TXT);
                var records = answers
                    .Where(answer => answer.Type == DnsRecordType.TXT)
                    .Select(answer => answer.TxtConcatenatedData.Trim())
                    .Where(IsSpfPolicyRecord)
                    .ToArray();
                return records.Length switch {
                    0 => (null, false, false),
                    1 => (records[0], false, false),
                    _ => (null, true, false)
                };
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger?.WriteWarningCode(SpfCodes.QueryFailed, "SPF lookup failed for {0}: {1}", name, ex.Message);
                return (null, false, true);
            }
        }

        async Task<HostEvaluationResult> EvaluateDomainAsync(string currentDomain, List<string> chain, bool useAnalyzedRecord) {
            if (!recursionPath.Add(currentDomain)) {
                return HostEvaluationResult.Error("permerror", currentDomain, chain);
            }

            try {
                var lookup = await GetRecordAsync(currentDomain, useAnalyzedRecord);
                if (lookup.Failed) {
                    return HostEvaluationResult.Error("temperror", currentDomain, chain);
                }
                if (lookup.Multiple) {
                    return HostEvaluationResult.Error("permerror", currentDomain, chain);
                }
                if (string.IsNullOrWhiteSpace(lookup.Record)) {
                    return HostEvaluationResult.Error("none", currentDomain, chain);
                }

                var tokens = TokenizeSpfRecord(lookup.Record!).Select(token => token.Trim('"')).ToArray();
                if (tokens.Length == 0 || !tokens[0].Equals("v=spf1", StringComparison.OrdinalIgnoreCase)) {
                    return HostEvaluationResult.Error("none", currentDomain, chain);
                }

                string? redirect = null;
                foreach (var rawToken in tokens.Skip(1)) {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (string.IsNullOrWhiteSpace(rawToken)) {
                        continue;
                    }

                    if (rawToken.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)) {
                        if (redirect != null) {
                            return HostEvaluationResult.Error("permerror", currentDomain, chain);
                        }
                        redirect = rawToken.Substring("redirect=".Length);
                        continue;
                    }
                    if (rawToken.IndexOf('=') >= 0) {
                        // Unknown modifiers are ignored by RFC 7208.
                        continue;
                    }

                    var qualifier = rawToken.Length > 0 && "+-~?".IndexOf(rawToken[0]) >= 0 ? rawToken[0] : '+';
                    var token = rawToken.TrimStart('+', '-', '~', '?');
                    var qualifiedVerdict = QualifierVerdict(qualifier);

                    if (token.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase) || token.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) {
                        var expectedFamily = token.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)
                            ? AddressFamily.InterNetwork
                            : AddressFamily.InterNetworkV6;
                        var cidr = token.Substring(4);
                        if (!TryIpMatchesCidr(ip, cidr, expectedFamily, out var matches)) {
                            return HostEvaluationResult.Match("permerror", rawToken, expectedFamily == AddressFamily.InterNetwork ? "ip4" : "ip6", currentDomain, chain);
                        }
                        if (matches) {
                            return HostEvaluationResult.Match(qualifiedVerdict, rawToken, expectedFamily == AddressFamily.InterNetwork ? "ip4" : "ip6", currentDomain, chain);
                        }
                        continue;
                    }

                    if (token.Equals("a", StringComparison.OrdinalIgnoreCase) || token.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || token.StartsWith("a/", StringComparison.OrdinalIgnoreCase)) {
                        if (!ConsumeLookup()) {
                            return HostEvaluationResult.Match("permerror", rawToken, "a", currentDomain, chain);
                        }
                        if (!TryParseDualCidrMechanism(token, "a", currentDomain, out var target, out var ipv4Prefix, out var ipv6Prefix)) {
                            return HostEvaluationResult.Match("permerror", rawToken, "a", currentDomain, chain);
                        }
                        target = await ExpandMacrosAsync(target, ip, evaluation.Sender, evaluation.Helo, currentDomain, logger);
                        try {
                            var type = ip.AddressFamily == AddressFamily.InterNetwork ? DnsRecordType.A : DnsRecordType.AAAA;
                            var answers = await QueryAsync(target, type);
                            var prefix = ip.AddressFamily == AddressFamily.InterNetwork ? ipv4Prefix : ipv6Prefix;
                            if (AnswersContainAddress(answers, ip, prefix)) {
                                return HostEvaluationResult.Match(qualifiedVerdict, rawToken, "a", currentDomain, chain);
                            }
                        } catch (OperationCanceledException) {
                            throw;
                        } catch {
                            return HostEvaluationResult.Match("temperror", rawToken, "a", currentDomain, chain);
                        }
                        continue;
                    }

                    if (token.Equals("mx", StringComparison.OrdinalIgnoreCase) || token.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || token.StartsWith("mx/", StringComparison.OrdinalIgnoreCase)) {
                        if (!ConsumeLookup()) {
                            return HostEvaluationResult.Match("permerror", rawToken, "mx", currentDomain, chain);
                        }
                        if (!TryParseDualCidrMechanism(token, "mx", currentDomain, out var target, out var ipv4Prefix, out var ipv6Prefix)) {
                            return HostEvaluationResult.Match("permerror", rawToken, "mx", currentDomain, chain);
                        }
                        target = await ExpandMacrosAsync(target, ip, evaluation.Sender, evaluation.Helo, currentDomain, logger);
                        try {
                            var mxAnswers = await QueryAsync(target, DnsRecordType.MX);
                            if (mxAnswers.Length > 10) {
                                return HostEvaluationResult.Match("permerror", rawToken, "mx", currentDomain, chain);
                            }
                            foreach (var mxAnswer in mxAnswers) {
                                var mxHost = ParseMxHost(mxAnswer.Data ?? mxAnswer.DataRaw);
                                if (string.IsNullOrWhiteSpace(mxHost)) {
                                    continue;
                                }
                                var type = ip.AddressFamily == AddressFamily.InterNetwork ? DnsRecordType.A : DnsRecordType.AAAA;
                                var addressAnswers = await QueryAsync(mxHost, type);
                                var prefix = ip.AddressFamily == AddressFamily.InterNetwork ? ipv4Prefix : ipv6Prefix;
                                if (AnswersContainAddress(addressAnswers, ip, prefix)) {
                                    return HostEvaluationResult.Match(qualifiedVerdict, rawToken, "mx", currentDomain, chain);
                                }
                            }
                        } catch (OperationCanceledException) {
                            throw;
                        } catch {
                            return HostEvaluationResult.Match("temperror", rawToken, "mx", currentDomain, chain);
                        }
                        continue;
                    }

                    if (token.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) {
                        if (!ConsumeLookup()) {
                            return HostEvaluationResult.Match("permerror", rawToken, "exists", currentDomain, chain);
                        }
                        var target = token.Substring("exists:".Length);
                        if (string.IsNullOrWhiteSpace(target)) {
                            return HostEvaluationResult.Match("permerror", rawToken, "exists", currentDomain, chain);
                        }
                        target = await ExpandMacrosAsync(target, ip, evaluation.Sender, evaluation.Helo, currentDomain, logger);
                        try {
                            var answers = await QueryAsync(target, DnsRecordType.A);
                            if (answers.Any(answer => answer.Type == DnsRecordType.A)) {
                                return HostEvaluationResult.Match(qualifiedVerdict, rawToken, "exists", currentDomain, chain);
                            }
                        } catch (OperationCanceledException) {
                            throw;
                        } catch {
                            return HostEvaluationResult.Match("temperror", rawToken, "exists", currentDomain, chain);
                        }
                        continue;
                    }

                    if (token.Equals("ptr", StringComparison.OrdinalIgnoreCase) || token.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)) {
                        if (!ConsumeLookup()) {
                            return HostEvaluationResult.Match("permerror", rawToken, "ptr", currentDomain, chain);
                        }
                        var target = token.Length > 3 ? token.Substring(4) : currentDomain;
                        target = await ExpandMacrosAsync(target, ip, evaluation.Sender, evaluation.Helo, currentDomain, logger);
                        try {
                            var ptrAnswers = await QueryAsync(ToReverseDnsName(ip), DnsRecordType.PTR);
                            if (ptrAnswers.Length > 10) {
                                return HostEvaluationResult.Match("permerror", rawToken, "ptr", currentDomain, chain);
                            }
                            foreach (var ptrAnswer in ptrAnswers) {
                                var ptrHost = (ptrAnswer.Data ?? ptrAnswer.DataRaw ?? string.Empty).Trim().TrimEnd('.');
                                if (!IsSameOrSubdomain(ptrHost, target)) {
                                    continue;
                                }
                                var type = ip.AddressFamily == AddressFamily.InterNetwork ? DnsRecordType.A : DnsRecordType.AAAA;
                                var forward = await QueryAsync(ptrHost, type);
                                if (AnswersContainAddress(forward, ip, ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128)) {
                                    return HostEvaluationResult.Match(qualifiedVerdict, rawToken, "ptr", currentDomain, chain);
                                }
                            }
                        } catch (OperationCanceledException) {
                            throw;
                        } catch {
                            return HostEvaluationResult.Match("temperror", rawToken, "ptr", currentDomain, chain);
                        }
                        continue;
                    }

                    if (token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                        if (!ConsumeLookup()) {
                            return HostEvaluationResult.Match("permerror", rawToken, "include", currentDomain, chain);
                        }
                        var includeDomain = token.Substring("include:".Length);
                        if (string.IsNullOrWhiteSpace(includeDomain)) {
                            return HostEvaluationResult.Match("permerror", rawToken, "include", currentDomain, chain);
                        }
                        includeDomain = await ExpandMacrosAsync(includeDomain, ip, evaluation.Sender, evaluation.Helo, currentDomain, logger);
                        var includeChain = new List<string>(chain) { includeDomain };
                        var included = await EvaluateDomainAsync(includeDomain, includeChain, false);
                        if (included.Verdict == "pass") {
                            return HostEvaluationResult.Match(qualifiedVerdict, rawToken, "include", currentDomain, includeChain);
                        }
                        if (included.Verdict == "temperror" || included.Verdict == "permerror") {
                            return HostEvaluationResult.Match(included.Verdict, rawToken, "include", currentDomain, includeChain);
                        }
                        if (included.Verdict == "none") {
                            return HostEvaluationResult.Match("permerror", rawToken, "include", currentDomain, includeChain);
                        }
                        continue;
                    }

                    if (IsAllMechanism(token)) {
                        return HostEvaluationResult.Match(qualifiedVerdict, rawToken, "all", currentDomain, chain);
                    }

                    return HostEvaluationResult.Match("permerror", rawToken, "unknown", currentDomain, chain);
                }

                if (redirect != null) {
                    if (!ConsumeLookup()) {
                        return HostEvaluationResult.Match("permerror", "redirect=" + redirect, "redirect", currentDomain, chain);
                    }
                    if (string.IsNullOrWhiteSpace(redirect)) {
                        return HostEvaluationResult.Match("permerror", "redirect=", "redirect", currentDomain, chain);
                    }
                    redirect = await ExpandMacrosAsync(redirect, ip, evaluation.Sender, evaluation.Helo, currentDomain, logger);
                    var redirectChain = new List<string>(chain) { redirect };
                    var redirected = await EvaluateDomainAsync(redirect, redirectChain, false);
                    if (redirected.Verdict == "none") {
                        return HostEvaluationResult.Match("permerror", "redirect=" + redirect, "redirect", currentDomain, redirectChain);
                    }
                    return redirected;
                }

                return HostEvaluationResult.Error("neutral", currentDomain, chain);
            } finally {
                recursionPath.Remove(currentDomain);
            }
        }

        var result = await EvaluateDomainAsync(domain, new List<string> { domain }, true);
        evaluation.DnsLookups = lookups;
        evaluation.Verdict = result.Verdict;
        evaluation.MatchedToken = result.Token;
        evaluation.MatchedType = result.Type;
        evaluation.MatchedDomain = result.Domain;
        evaluation.Chain = result.Chain;
        return evaluation;
    }

    private static string QualifierVerdict(char qualifier) {
        return qualifier switch {
            '+' => "pass",
            '-' => "fail",
            '~' => "softfail",
            '?' => "neutral",
            _ => "neutral"
        };
    }

    private static bool IsSpfPolicyRecord(string value) {
        return value.Equals("v=spf1", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("v=spf1 ", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryIpMatchesCidr(IPAddress candidate, string cidr, AddressFamily expectedFamily, out bool matches) {
        matches = false;
        var parts = cidr.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var network) || network.AddressFamily != expectedFamily) {
            return false;
        }
        var maximum = expectedFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = maximum;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > maximum)) {
            return false;
        }
        if (candidate.AddressFamily != expectedFamily) {
            return true;
        }
        matches = PrefixMatches(candidate, network, prefix);
        return true;
    }

    private static bool TryParseDualCidrMechanism(string token, string mechanism, string defaultDomain, out string domain, out int ipv4Prefix, out int ipv6Prefix) {
        domain = defaultDomain;
        ipv4Prefix = 32;
        ipv6Prefix = 128;
        var suffix = token.Substring(mechanism.Length);

        var doubleSlash = suffix.IndexOf("//", StringComparison.Ordinal);
        if (doubleSlash >= 0) {
            var ipv6Text = suffix.Substring(doubleSlash + 2);
            if (!int.TryParse(ipv6Text, out ipv6Prefix) || ipv6Prefix < 0 || ipv6Prefix > 128) {
                return false;
            }
            suffix = suffix.Substring(0, doubleSlash);
        }

        var singleSlash = suffix.LastIndexOf('/');
        if (singleSlash >= 0) {
            var ipv4Text = suffix.Substring(singleSlash + 1);
            if (!int.TryParse(ipv4Text, out ipv4Prefix) || ipv4Prefix < 0 || ipv4Prefix > 32) {
                return false;
            }
            suffix = suffix.Substring(0, singleSlash);
        }

        if (suffix.Length == 0) {
            return true;
        }
        if (!suffix.StartsWith(":", StringComparison.Ordinal) || suffix.Length == 1) {
            return false;
        }
        domain = suffix.Substring(1);
        return true;
    }

    private static bool AnswersContainAddress(IEnumerable<DnsAnswer> answers, IPAddress candidate, int prefixLength) {
        foreach (var answer in answers) {
            if (IPAddress.TryParse(answer.Data ?? answer.DataRaw, out var address) &&
                address.AddressFamily == candidate.AddressFamily &&
                PrefixMatches(candidate, address, prefixLength)) {
                return true;
            }
        }
        return false;
    }

    private static bool PrefixMatches(IPAddress candidate, IPAddress network, int prefixLength) {
        var candidateBytes = candidate.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        if (candidateBytes.Length != networkBytes.Length || prefixLength < 0 || prefixLength > candidateBytes.Length * 8) {
            return false;
        }
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;
        for (var index = 0; index < fullBytes; index++) {
            if (candidateBytes[index] != networkBytes[index]) {
                return false;
            }
        }
        if (remainingBits == 0) {
            return true;
        }
        var mask = (byte)(0xFF << (8 - remainingBits));
        return (candidateBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }

    private static string ParseMxHost(string value) {
        var parts = (value ?? string.Empty).Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        return (parts.Length > 1 ? parts[parts.Length - 1] : parts.FirstOrDefault() ?? string.Empty).TrimEnd('.');
    }

    private static bool IsSameOrSubdomain(string candidate, string domain) {
        return candidate.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
               candidate.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
    }

    private static string ToReverseDnsName(IPAddress address) {
        if (address.AddressFamily == AddressFamily.InterNetwork) {
            var bytes = address.GetAddressBytes();
            Array.Reverse(bytes);
            return string.Join(".", bytes.Select(value => value.ToString())) + ".in-addr.arpa";
        }
        var hex = string.Concat(address.GetAddressBytes().Select(value => value.ToString("x2")));
        return string.Join(".", hex.Reverse().Select(character => character.ToString())) + ".ip6.arpa";
    }

    private sealed class HostEvaluationResult {
        public string Verdict { get; private set; } = "neutral";
        public string? Token { get; private set; }
        public string? Type { get; private set; }
        public string? Domain { get; private set; }
        public List<string> Chain { get; private set; } = new();

        public static HostEvaluationResult Match(string verdict, string token, string type, string domain, List<string> chain) {
            return new HostEvaluationResult { Verdict = verdict, Token = token, Type = type, Domain = domain, Chain = new List<string>(chain) };
        }

        public static HostEvaluationResult Error(string verdict, string domain, List<string> chain) {
            return new HostEvaluationResult { Verdict = verdict, Domain = domain, Chain = new List<string>(chain) };
        }
    }
}
