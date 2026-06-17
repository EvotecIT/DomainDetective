using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainDetective {
    public partial class MessageHeaderAnalysis {
        private static readonly Regex SemicolonTokenRegex = new(@"(?<key>[A-Z0-9]+):(?<value>[^;]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

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
        public void CompareExpectedMx(IEnumerable<string>? expectedMxHosts) {
            ExpectedMxHosts.Clear();
            ExpectedMxObserved = false;
            ExpectedMxBypassed = false;

            if (expectedMxHosts == null) {
                return;
            }

            foreach (var host in expectedMxHosts) {
                if (!string.IsNullOrWhiteSpace(host)) {
                    ExpectedMxHosts.Add(host.Trim());
                }
            }

            if (ExpectedMxHosts.Count == 0) {
                return;
            }

            ExpectedMxObserved = ExpectedMxHosts.Any(IsHostObserved);
            ExpectedMxBypassed = !ExpectedMxObserved && DirectToExchangeOnlineObserved;
            if (ExpectedMxBypassed) {
                AddIssue(MessageHeaderIssue.ExpectedMxBypassed);
            }
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
            NetworkMessageId = GetHeaderValue("X-MS-Exchange-Organization-Network-Message-Id");
            CrossTenantNetworkMessageId = GetHeaderValue("X-MS-Exchange-CrossTenant-Network-Message-Id");
            ExchangeAuthAs = GetHeaderValue("X-MS-Exchange-Organization-AuthAs");
            CrossTenantAuthAs = GetHeaderValue("X-MS-Exchange-CrossTenant-AuthAs");
            ExternalInOutlookResult = GetHeaderValue("X-MS-Exchange-ExternalInOutlookResult");

            if (int.TryParse(GetHeaderValue("X-MS-Exchange-Organization-SCL"), out var scl)) {
                Scl = scl;
            }

            var delivery = GetHeaderValue("X-Microsoft-Antispam-Mailbox-Delivery");
            MailboxDestination = ExtractToken(delivery, "dest");
            DeliveredToInbox = string.Equals(MailboxDestination, "I", StringComparison.OrdinalIgnoreCase);

            var forefront = GetHeaderValue("X-Forefront-Antispam-Report");
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
            GatewayLoopDetected = RedirectedToProofpoint && ReceivedFromProofpoint;
            DirectToExchangeOnlineObserved = SeenMicrosoftEop
                && !string.IsNullOrWhiteSpace(ForefrontSourceIp)
                && string.Equals(ExchangeAuthAs, "Anonymous", StringComparison.OrdinalIgnoreCase);

            DmarcFailed = IsFailureResult(DmarcResult, treatMissingAsFailure: false);
            DkimMissingOrFailed = IsFailureResult(DkimResult, treatMissingAsFailure: true);
            SpfFailedOrSoftFailed = IsFailureResult(SpfResult, treatMissingAsFailure: false);
            SameDomainSelfSpoof = TryGetDomain(From, out var fromDomain)
                && TryGetDomain(To, out var toDomain)
                && string.Equals(fromDomain, toDomain, StringComparison.OrdinalIgnoreCase);

            AuthenticationFailedDeliveredToInbox = DeliveredToInbox && (DmarcFailed || DkimMissingOrFailed || SpfFailedOrSoftFailed);
            SelfSpoofDeliveredToInbox = DeliveredToInbox && SameDomainSelfSpoof;

            if (GatewayLoopDetected) {
                logger?.WriteWarningCode(MessageHeaderCodes.GatewayLoopDetected, "Message headers show Exchange Online routing to Proofpoint and returning to Exchange Online.");
            }
            if (DirectToExchangeOnlineObserved) {
                logger?.WriteWarningCode(MessageHeaderCodes.DirectToExchangeOnlineObserved, "Message appears to have entered Exchange Online directly from {0}.", ForefrontSourceIp ?? "unknown source");
            }
            if (AuthenticationFailedDeliveredToInbox) {
                logger?.WriteWarningCode(MessageHeaderCodes.AuthenticationFailedDeliveredToInbox, "Message reached Inbox even though SPF, DKIM, or DMARC did not pass.");
            }
            if (SelfSpoofDeliveredToInbox) {
                logger?.WriteWarningCode(MessageHeaderCodes.SelfSpoofDeliveredToInbox, "Message appears to be same-domain self-spoofing and was delivered to Inbox.");
            }
        }

        private void DetermineRouteIssues() {
            if (GatewayLoopDetected) {
                AddIssue(MessageHeaderIssue.GatewayLoopDetected);
            }
            if (DirectToExchangeOnlineObserved) {
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

        private bool HasHeaderPrefix(string prefix) {
            return Headers.Keys.Any(key => key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }

        private bool HasHeaderContaining(string text) {
            return Headers.Keys.Any(key => key.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private bool IsHostObserved(string host) {
            return Headers.Any(header => ContainsProvider(header.Value, host))
                || ReceivedHops.Any(hop => ContainsProvider(hop.Raw, host));
        }

        private static string? ExtractToken(string? value, string key) {
            if (string.IsNullOrWhiteSpace(value)) {
                return null;
            }

            foreach (Match match in SemicolonTokenRegex.Matches(value)) {
                if (string.Equals(match.Groups["key"].Value, key, StringComparison.OrdinalIgnoreCase)) {
                    return match.Groups["value"].Value.Trim();
                }
            }

            return null;
        }

        private static bool ContainsProvider(string value, string provider) {
            return value.IndexOf(provider, StringComparison.OrdinalIgnoreCase) >= 0;
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
