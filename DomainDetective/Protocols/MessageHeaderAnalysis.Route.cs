using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainDetective {
    public partial class MessageHeaderAnalysis {
        private static readonly Regex SemicolonTokenRegex = new(@"(?<key>[A-Z0-9]+):(?<value>[^;]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private bool _rawDirectToExchangeOnlineObserved;

        /// <summary>Value of the <c>Message-ID</c> header.</summary>
        public string? MessageId { get; private set; }
        /// <summary>Microsoft network message identifier when present.</summary>
        public string? NetworkMessageId { get; private set; }
        /// <summary>Microsoft cross-tenant network message identifier when present.</summary>
        public string? CrossTenantNetworkMessageId { get; private set; }
        /// <summary>Authentication attribution reported by Exchange Online.</summary>
        public string? ExchangeAuthAs { get; private set; }
        /// <summary>Cross-tenant authentication attribution reported by Exchange Online.</summary>
        public string? CrossTenantAuthAs { get; private set; }
        /// <summary>Spam confidence level reported by Exchange Online.</summary>
        public int? Scl { get; private set; }
        /// <summary>Mailbox destination parsed from Microsoft anti-spam delivery headers.</summary>
        public string? MailboxDestination { get; private set; }
        /// <summary>Connecting IP parsed from <c>X-Forefront-Antispam-Report</c>.</summary>
        public string? ForefrontSourceIp { get; private set; }
        /// <summary>Source host parsed from <c>X-Forefront-Antispam-Report</c>.</summary>
        public string? ForefrontHost { get; private set; }
        /// <summary>Spam filtering verdict parsed from <c>X-Forefront-Antispam-Report</c>.</summary>
        public string? ForefrontSfv { get; private set; }
        /// <summary>External sender tagging result reported by Outlook/Exchange Online.</summary>
        public string? ExternalInOutlookResult { get; private set; }
        /// <summary>Indicates that Microsoft Exchange Online Protection headers or hops were observed.</summary>
        public bool SeenMicrosoftEop { get; private set; }
        /// <summary>Indicates that Proofpoint headers or hops were observed.</summary>
        public bool SeenProofpoint { get; private set; }
        /// <summary>Indicates that the message appears to have entered Exchange Online directly.</summary>
        public bool DirectToExchangeOnlineObserved { get; private set; }
        /// <summary>Indicates that Microsoft classified the delivered destination as Inbox.</summary>
        public bool DeliveredToInbox { get; private set; }
        /// <summary>Indicates that DMARC failed or did not produce a pass result.</summary>
        public bool DmarcFailed { get; private set; }
        /// <summary>Indicates that DKIM was missing, failed, or did not produce a pass result.</summary>
        public bool DkimMissingOrFailed { get; private set; }
        /// <summary>Indicates that SPF failed, soft-failed, or did not produce a pass result.</summary>
        public bool SpfFailedOrSoftFailed { get; private set; }
        /// <summary>Indicates that From and To use the same address domain.</summary>
        public bool SameDomainSelfSpoof { get; private set; }
        /// <summary>Indicates that Microsoft headers show routing toward Proofpoint after Exchange Online.</summary>
        public bool RedirectedToProofpoint { get; private set; }
        /// <summary>Indicates that Microsoft headers show a message returning from Proofpoint.</summary>
        public bool ReceivedFromProofpoint { get; private set; }
        /// <summary>Indicates a likely EOP to gateway to EOP processing loop.</summary>
        public bool GatewayLoopDetected { get; private set; }
        /// <summary>Indicates failed authentication on a message that still reached Inbox.</summary>
        public bool AuthenticationFailedDeliveredToInbox { get; private set; }
        /// <summary>Indicates same-domain self-spoofing on a message that still reached Inbox.</summary>
        public bool SelfSpoofDeliveredToInbox { get; private set; }
        /// <summary>Expected public MX hosts supplied by the caller for route comparison.</summary>
        public List<string> ExpectedMxHosts { get; } = new();
        /// <summary>Indicates that at least one expected public MX host appears in the observed route.</summary>
        public bool ExpectedMxObserved { get; private set; }
        /// <summary>Indicates that expected MX hosts were not observed while direct Exchange Online ingress was observed.</summary>
        public bool ExpectedMxBypassed { get; private set; }
        /// <summary>First likely external source IP from structured Microsoft headers or Received hops.</summary>
        public string? SourceIp => ForefrontSourceIp ?? ReceivedHops.FirstOrDefault(static hop => !string.IsNullOrWhiteSpace(hop.FromIp))?.FromIp;

        /// <summary>
        /// Compares the observed message path with expected public MX host names.
        /// </summary>
        /// <param name="expectedMxHosts">Public MX host names expected to process inbound mail first.</param>
        /// <param name="logger">Optional logger used to attach expected-MX route findings to assessments.</param>
        public void CompareExpectedMx(IEnumerable<string>? expectedMxHosts, InternalLogger? logger = null) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "HEADERS") : null;
            ExpectedMxHosts.Clear();
            ExpectedMxObserved = false;
            ExpectedMxBypassed = false;
            DirectToExchangeOnlineObserved = _rawDirectToExchangeOnlineObserved;
            Issues.Remove(MessageHeaderIssue.ExpectedMxBypassed);
            Issues.Remove(MessageHeaderIssue.DirectToExchangeOnline);
            RemoveAssessment(MessageHeaderCodes.ExpectedMxBypassed);
            RemoveAssessment(MessageHeaderCodes.DirectToExchangeOnlineObserved);

            if (expectedMxHosts == null) {
                EmitRouteDiagnostics(logger);
                return;
            }

            foreach (var host in expectedMxHosts.Where(static host => !string.IsNullOrWhiteSpace(host))) {
                var normalized = NormalizeHost(host);
                if (normalized.Length > 0 && !ExpectedMxHosts.Contains(normalized, StringComparer.OrdinalIgnoreCase)) {
                    ExpectedMxHosts.Add(normalized);
                }
            }

            if (ExpectedMxHosts.Count == 0) {
                EmitRouteDiagnostics(logger);
                return;
            }

            ExpectedMxObserved = ExpectedMxHosts.Any(IsHostObservedAtMicrosoftIngress);
            if (ExpectedMxObserved) {
                DirectToExchangeOnlineObserved = false;
                Issues.Remove(MessageHeaderIssue.DirectToExchangeOnline);
                RemoveAssessment(MessageHeaderCodes.DirectToExchangeOnlineObserved);
            }

            ExpectedMxBypassed = !ExpectedMxObserved && _rawDirectToExchangeOnlineObserved;
            if (ExpectedMxBypassed) {
                AddIssue(MessageHeaderIssue.DirectToExchangeOnline);
                AddIssue(MessageHeaderIssue.ExpectedMxBypassed);
            }

            EmitRouteDiagnostics(logger);
        }

        private void ResetRouteDiagnostics() {
            MessageId = null;
            NetworkMessageId = null;
            CrossTenantNetworkMessageId = null;
            ExchangeAuthAs = null;
            CrossTenantAuthAs = null;
            Scl = null;
            MailboxDestination = null;
            ForefrontSourceIp = null;
            ForefrontHost = null;
            ForefrontSfv = null;
            ExternalInOutlookResult = null;
            SeenMicrosoftEop = false;
            SeenProofpoint = false;
            _rawDirectToExchangeOnlineObserved = false;
            DirectToExchangeOnlineObserved = false;
            DeliveredToInbox = false;
            DmarcFailed = false;
            DkimMissingOrFailed = false;
            SpfFailedOrSoftFailed = false;
            SameDomainSelfSpoof = false;
            RedirectedToProofpoint = false;
            ReceivedFromProofpoint = false;
            GatewayLoopDetected = false;
            AuthenticationFailedDeliveredToInbox = false;
            SelfSpoofDeliveredToInbox = false;
            ExpectedMxHosts.Clear();
            ExpectedMxObserved = false;
            ExpectedMxBypassed = false;
        }

        private void AnalyzeRouteHeaders(InternalLogger? logger) {
            MessageId = GetHeaderValue("Message-ID");
            NetworkMessageId = GetTrustedHeaderValue("X-MS-Exchange-Organization-Network-Message-Id");
            CrossTenantNetworkMessageId = GetTrustedHeaderValue("X-MS-Exchange-CrossTenant-Network-Message-Id");
            ExchangeAuthAs = GetTrustedHeaderValue("X-MS-Exchange-Organization-AuthAs");
            CrossTenantAuthAs = GetTrustedHeaderValue("X-MS-Exchange-CrossTenant-AuthAs");
            ExternalInOutlookResult = GetTrustedHeaderValue("X-MS-Exchange-ExternalInOutlookResult");

            if (int.TryParse(GetTrustedHeaderValue("X-MS-Exchange-Organization-SCL"), out var scl)) {
                Scl = scl;
            }

            var delivery = GetTrustedHeaderValue("X-Microsoft-Antispam-Mailbox-Delivery");
            MailboxDestination = ExtractToken(delivery, "dest");
            DeliveredToInbox = string.Equals(MailboxDestination, "I", StringComparison.OrdinalIgnoreCase);

            var forefront = GetTrustedHeaderValue("X-Forefront-Antispam-Report");
            ForefrontSourceIp = ExtractToken(forefront, "CIP");
            ForefrontHost = ExtractToken(forefront, "H");
            ForefrontSfv = ExtractToken(forefront, "SFV");
            if (!Scl.HasValue && int.TryParse(ExtractToken(forefront, "SCL"), out var forefrontScl)) {
                Scl = forefrontScl;
            }

            SeenMicrosoftEop = HasHeaderPrefix("X-MS-Exchange-")
                || HasHeaderPrefix("X-Microsoft-Antispam")
                || HasHeaderPrefix("X-Forefront-")
                || ReceivedHops.Any(static hop => ContainsProvider(hop.Raw, "protection.outlook.com") || ContainsProvider(hop.Raw, "prod.outlook.com"));
            SeenProofpoint = HasHeaderPrefix("X-Proofpoint")
                || HasHeaderContaining("Proofpoint")
                || ReceivedHops.Any(static hop => ContainsProvider(hop.Raw, "pphosted.com") || ContainsProvider(hop.Raw, "proofpoint"));

            RedirectedToProofpoint = HasHeaderContaining("RedirectToProofpoint");
            ReceivedFromProofpoint = HasHeaderContaining("EmailReceivedFromPP");
            GatewayLoopDetected = (RedirectedToProofpoint && ReceivedFromProofpoint) || HasGatewayLoopInReceivedRoute();
            _rawDirectToExchangeOnlineObserved = SeenMicrosoftEop
                && !string.IsNullOrWhiteSpace(ForefrontSourceIp)
                && IsAnonymousExchangeAuth();
            DirectToExchangeOnlineObserved = _rawDirectToExchangeOnlineObserved;

            DmarcFailed = IsFailureResult(TrustedDmarcResult, treatMissingAsFailure: false);
            DkimMissingOrFailed = IsFailureResult(TrustedDkimResult, treatMissingAsFailure: true);
            SpfFailedOrSoftFailed = IsFailureResult(TrustedSpfResult, treatMissingAsFailure: false);
            SameDomainSelfSpoof = TryGetDomain(From, out var fromDomain)
                && TryGetDomain(To, out var toDomain)
                && string.Equals(fromDomain, toDomain, StringComparison.OrdinalIgnoreCase);

            AuthenticationFailedDeliveredToInbox = DeliveredToInbox && DmarcFailed;
            SelfSpoofDeliveredToInbox = DeliveredToInbox
                && SameDomainSelfSpoof
                && (DirectToExchangeOnlineObserved || AuthenticationFailedDeliveredToInbox || IsAnonymousExchangeAuth());

        }

        private void DetermineRouteIssues() {
            if (GatewayLoopDetected) {
                AddIssue(MessageHeaderIssue.GatewayLoopDetected);
            }
            if (DirectToExchangeOnlineObserved && ExpectedMxBypassed) {
                AddIssue(MessageHeaderIssue.DirectToExchangeOnline);
            }
            if (AuthenticationFailedDeliveredToInbox) {
                AddIssue(MessageHeaderIssue.AuthenticationFailedDeliveredToInbox);
            }
            if (SelfSpoofDeliveredToInbox) {
                AddIssue(MessageHeaderIssue.SelfSpoofDeliveredToInbox);
            }
            if (ExpectedMxBypassed) {
                AddIssue(MessageHeaderIssue.ExpectedMxBypassed);
            }
        }

        private string? GetHeaderValue(string name) {
            return Headers.TryGetValue(name, out var value) ? value : null;
        }

        private string? GetTrustedHeaderValue(string name) {
            if (DuplicateHeaders.TryGetValue(name, out var values) && values.Count > 0) {
                return values[0];
            }

            return GetHeaderValue(name);
        }

        private bool HasHeaderPrefix(string prefix) {
            return Headers.Keys.Any(key => key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }

        private bool HasHeaderContaining(string text) {
            return Headers.Keys.Any(key => key.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private bool IsHostObservedAtMicrosoftIngress(string host) {
            var ingressHop = ReceivedHops
                .Where(hop => IsMicrosoftEopHost(hop.ByHost))
                .OrderBy(hop => hop.HeaderIndex)
                .FirstOrDefault();
            return ingressHop != null
                && (IsSameHost(ingressHop.FromHost, host)
                    || (IsMicrosoftEopHost(host) && IsSameHost(ingressHop.ByHost, host)));
        }

        private static string? ExtractToken(string? value, string key) {
            if (string.IsNullOrWhiteSpace(value)) {
                return null;
            }

            foreach (Match match in SemicolonTokenRegex.Matches(value).Cast<Match>().Where(match => string.Equals(match.Groups["key"].Value, key, StringComparison.OrdinalIgnoreCase))) {
                return match.Groups["value"].Value.Trim();
            }

            return null;
        }

        private bool HasGatewayLoopInReceivedRoute() {
            var seenMicrosoftEopToGateway = false;
            foreach (var hop in ReceivedHops) {
                var fromMicrosoftEop = IsMicrosoftEopHost(hop.FromHost);
                var byMicrosoftEop = IsMicrosoftEopHost(hop.ByHost);
                var fromProofpoint = IsProofpointHost(hop.FromHost);
                var byProofpoint = IsProofpointHost(hop.ByHost);

                if (seenMicrosoftEopToGateway && fromProofpoint && byMicrosoftEop) {
                    return true;
                }

                if (fromMicrosoftEop && byProofpoint) {
                    seenMicrosoftEopToGateway = true;
                }
            }

            return false;
        }

        private static bool IsMicrosoftEopHost(string? value) {
            return ContainsProvider(value, "protection.outlook.com")
                || ContainsProvider(value, "prod.outlook.com");
        }

        private static bool IsProofpointHost(string? value) {
            return ContainsProvider(value, "pphosted.com")
                || ContainsProvider(value, "proofpoint");
        }

        private bool IsAnonymousExchangeAuth() {
            return string.Equals(ExchangeAuthAs, "Anonymous", StringComparison.OrdinalIgnoreCase)
                || string.Equals(CrossTenantAuthAs, "Anonymous", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeHost(string host) {
            return host.Trim().TrimEnd('.');
        }

        internal void EmitRouteDiagnostics(InternalLogger? logger = null) {
            if (GatewayLoopDetected) {
                WriteRouteWarning(logger, MessageHeaderCodes.GatewayLoopDetected, "Message headers show Exchange Online routing to Proofpoint and returning to Exchange Online.");
            }
            if (DirectToExchangeOnlineObserved && ExpectedMxBypassed) {
                WriteRouteWarning(logger, MessageHeaderCodes.DirectToExchangeOnlineObserved, "Message appears to have entered Exchange Online directly from {0}.", ForefrontSourceIp);
            }
            if (AuthenticationFailedDeliveredToInbox) {
                WriteRouteWarning(logger, MessageHeaderCodes.AuthenticationFailedDeliveredToInbox, "Message reached Inbox even though SPF, DKIM, or DMARC did not pass.");
            }
            if (SelfSpoofDeliveredToInbox) {
                WriteRouteWarning(logger, MessageHeaderCodes.SelfSpoofDeliveredToInbox, "Message appears to be same-domain self-spoofing and was delivered to Inbox.");
            }
            if (ExpectedMxBypassed) {
                WriteRouteWarning(logger, MessageHeaderCodes.ExpectedMxBypassed, "Expected public MX hosts were not observed in the message route.");
            }
        }

        private void WriteRouteWarning(InternalLogger? logger, string code, string message) {
            if (logger != null) {
                logger.WriteWarningCode(code, message);
                return;
            }

            if (Assessments.Any(assessment => string.Equals(assessment.Code, code, StringComparison.Ordinal))) {
                return;
            }

            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "HEADERS",
                Code = code,
                Message = message,
                Timestamp = DateTimeOffset.UtcNow
            });
        }

        private void WriteRouteWarning(InternalLogger? logger, string code, string message, params object?[] args) {
            if (logger != null) {
                logger.WriteWarningCode(code, message, args);
                return;
            }

            var formatted = args != null && args.Length > 0 ? string.Format(message, args) : message;
            if (Assessments.Any(assessment => string.Equals(assessment.Code, code, StringComparison.Ordinal))) {
                return;
            }

            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "HEADERS",
                Code = code,
                Message = formatted,
                Timestamp = DateTimeOffset.UtcNow
            });
        }

        private void RemoveAssessment(string code) {
            Assessments.RemoveAll(assessment => string.Equals(assessment.Code, code, StringComparison.Ordinal));
        }

        private static bool IsSameHost(string? value, string host) {
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            return string.Equals(NormalizeHost(value!), host, StringComparison.OrdinalIgnoreCase);
        }

        private static bool ContainsHostWithBoundary(string? value, string host) {
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            var startIndex = 0;
            while (startIndex < value!.Length) {
                var index = value.IndexOf(host, startIndex, StringComparison.OrdinalIgnoreCase);
                if (index < 0) {
                    return false;
                }

                if (HasHostBoundary(value, index, host.Length)) {
                    return true;
                }

                startIndex = index + host.Length;
            }

            return false;
        }

        private static bool HasHostBoundary(string value, int start, int length) {
            if (start > 0 && IsDnsHostCharacter(value[start - 1])) {
                return false;
            }

            var end = start + length;
            if (end >= value.Length) {
                return true;
            }

            if (value[end] == '.') {
                return end == value.Length - 1 || !IsDnsHostCharacter(value[end + 1]);
            }

            return !IsDnsHostCharacter(value[end]);
        }

        private static bool IsDnsHostCharacter(char value) {
            return char.IsLetterOrDigit(value) || value == '-' || value == '.';
        }

        private string? TrustedDkimResult => _hasTrustedAuthenticationResults ? _trustedDkimResult : DkimResult;

        private string? TrustedSpfResult => _hasTrustedAuthenticationResults ? _trustedSpfResult : SpfResult;

        private string? TrustedDmarcResult => _hasTrustedAuthenticationResults ? _trustedDmarcResult : DmarcResult;

        private static bool ContainsProvider(string? value, string provider) {
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            return value!.IndexOf(provider, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsFailureResult(string? result, bool treatMissingAsFailure) {
            if (string.IsNullOrWhiteSpace(result)) {
                return treatMissingAsFailure;
            }

            var normalized = result!.Trim();
            return normalized.StartsWith("fail", StringComparison.OrdinalIgnoreCase)
                || normalized.StartsWith("softfail", StringComparison.OrdinalIgnoreCase)
                || normalized.StartsWith("permerror", StringComparison.OrdinalIgnoreCase)
                || normalized.StartsWith("temperror", StringComparison.OrdinalIgnoreCase)
                || normalized.StartsWith("none", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExplicitFailureResult(string? result) {
            if (string.IsNullOrWhiteSpace(result)) {
                return false;
            }

            var normalized = result!.Trim();
            return normalized.StartsWith("fail", StringComparison.OrdinalIgnoreCase)
                || normalized.StartsWith("softfail", StringComparison.OrdinalIgnoreCase)
                || normalized.StartsWith("permerror", StringComparison.OrdinalIgnoreCase)
                || normalized.StartsWith("temperror", StringComparison.OrdinalIgnoreCase);
        }

        private static bool TryGetDomain(string? value, out string? domain) {
            domain = null;
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            if (!MailboxAddress.TryParse(value, out var address) || string.IsNullOrWhiteSpace(address.Address)) {
                return false;
            }

            var at = address.Address.LastIndexOf('@');
            if (at < 0 || at == address.Address.Length - 1) {
                return false;
            }

            domain = address.Address.Substring(at + 1);
            return true;
        }
    }
}
