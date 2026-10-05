using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Documented Microsoft header meanings. Unknown values are preserved without invented interpretations.</summary>
internal static class MessageVendorMeanings {
    // Source: https://learn.microsoft.com/defender-office-365/message-headers-eop-mdo
    private static readonly Dictionary<string, string> CompositeReasons = new(StringComparer.Ordinal) {
        ["000"] = "Reported explicit authentication failure with a DMARC quarantine or reject policy.",
        ["001"] = "Reported implicit authentication failure with absent authentication records or weaker policy.",
        ["002"] = "Reported explicit administrative prohibition of spoofing for the sender/domain pair.",
        ["010"] = "Reported DMARC failure for an accepted organization domain with quarantine or reject policy.",
        ["100"] = "Reported SPF or DKIM pass with aligned MAIL FROM and From domains.",
        ["101"] = "Reported DKIM signature from the From domain.",
        ["102"] = "Reported SPF pass with aligned MAIL FROM and From domains.",
        ["103"] = "Reported From-domain alignment with the source IP reverse DNS.",
        ["104"] = "Reported source IP reverse DNS alignment with the From domain.",
        ["108"] = "Reported DKIM failure attributed to body modification by previous legitimate hops.",
        ["109"] = "Reported authentication that would pass despite an absent DMARC record.",
        ["111"] = "Reported SPF or DKIM alignment despite a DMARC error.",
        ["112"] = "Reported DNS timeout while retrieving DMARC.",
        ["115"] = "Reported sending Microsoft 365 organization with the From domain configured as an accepted domain.",
        ["116"] = "Reported From-domain MX alignment with connecting-IP reverse DNS.",
        ["130"] = "Receiver reports that a trusted ARC sealer result overrode DMARC failure.",
        ["201"] = "Reported From-domain reverse DNS alignment with the connecting-IP reverse DNS subnet.",
        ["202"] = "Reported From-domain alignment with connecting-IP reverse DNS.",
        ["501"] = "Reported valid non-delivery report with established sender/recipient contact; DMARC not enforced.",
        ["502"] = "Reported valid non-delivery report for an organization-sent message; DMARC not enforced.",
        ["601"] = "Reported implicit authentication failure involving an accepted organization domain.",
        ["905"] = "Reported DMARC non-enforcement due to complex routing."
    };

    internal static string? CompositeReason(string? code) {
        if (code == null) { return null; }
        if (CompositeReasons.TryGetValue(code, out var meaning)) { return meaning; }
        if (code.Length == 3 && int.TryParse(code, out var value)) {
            if (value >= 701 && value <= 704) { return "Reported DMARC non-enforcement based on established legitimate sending infrastructure."; }
            return code[0] switch {
                '1' => "Reported explicit or implicit authentication pass (1xx family).",
                '2' => "Reported implicit authentication soft pass (2xx family).",
                '3' => "Composite authentication not checked (3xx family).",
                '4' => "Composite authentication bypassed (4xx family).",
                '6' => "Reported implicit authentication failure (6xx family).",
                '7' => "Reported implicit authentication pass (7xx family).",
                '9' => "Composite authentication bypassed (9xx family).",
                _ => "Unknown reason; raw code preserved."
            };
        }
        return "Unknown reason; raw code preserved.";
    }

    private static readonly Dictionary<string, string> Filtering = new(StringComparer.OrdinalIgnoreCase) {
        ["CAT:AMP"] = "Anti-malware", ["CAT:BIMP"] = "Brand impersonation", ["CAT:BULK"] = "Bulk mail", ["CAT:DIMP"] = "Domain impersonation",
        ["CAT:FTBP"] = "Common attachment filter", ["CAT:GIMP"] = "Mailbox intelligence impersonation", ["CAT:HPHSH"] = "High-confidence phishing",
        ["CAT:HPHISH"] = "High-confidence phishing", ["CAT:HSPM"] = "High-confidence spam", ["CAT:INTOS"] = "Intra-organization phishing",
        ["CAT:MALW"] = "Malware", ["CAT:OSPM"] = "Outbound spam", ["CAT:PHSH"] = "Phishing", ["CAT:SAP"] = "Safe Attachments",
        ["CAT:SPM"] = "Spam", ["CAT:SPOOF"] = "Spoofing", ["CAT:UIMP"] = "User impersonation",
        ["DIR:INB"] = "Inbound", ["DIR:OUT"] = "Outbound", ["DIR:INT"] = "Internal",
        ["IPV:CAL"] = "Receiver reports IP allow-list filtering bypass", ["IPV:NLI"] = "IP absent from reputation lists",
        ["SFV:BLK"] = "Blocked sender list", ["SFV:NSPM"] = "Filtering classified nonspam", ["SFV:SFE"] = "Safe sender list bypass",
        ["SFV:SKA"] = "Policy sender/domain allow-list bypass", ["SFV:SKB"] = "Policy sender/domain block-list spam",
        ["SFV:SKI"] = "Connection filter IP allow-list bypass", ["SFV:SKN"] = "Mail-flow rule filtering bypass",
        ["SFV:SKQ"] = "Released from quarantine", ["SFV:SKS"] = "Pre-filter spam classification honored", ["SFV:SPM"] = "Filtering classified spam",
        ["SRV:BULK"] = "Bulk mail classification"
    };

    internal static string FilteringMeaning(string key, string value) => Filtering.TryGetValue(key + ":" + value, out var meaning) ? meaning
        : key.Equals("BCL", StringComparison.OrdinalIgnoreCase) ? "Bulk complaint level; higher values indicate greater complaint likelihood."
        : key.Equals("SCL", StringComparison.OrdinalIgnoreCase) ? "Reported spam confidence; cloud delivery decisions require category, direction, and policy context."
        : "Raw diagnostic value; no documented interpretation asserted.";
}
