using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed partial class MessageHeaderRecommendations {
    private static void RegisterEvidenceAdvice(IDictionary<string, RecommendationAdvice> map) {
        void Add(string code, string title, string why, string how, string verify) {
            map[code] = new RecommendationAdvice { Code = code, Title = title, Why = why, How = how, Verify = verify, Domain = RecommendationDomain.EmailAuth, Tags = new[] { "headers", "evidence" } };
        }
        Add("HEADERS.Exchange.ExternallySecured", "Review externally secured connector attribution",
            "The header reports connector classification; it does not prove that filtering or connector restrictions were enforced.",
            "Compare message trace with the receiving connector's approved sources, authentication settings and filtering behavior. Review any bypass rules before changing policy.",
            "Confirm the actual connector and filtering outcome for this message in receiver logs.");
        Add("HEADERS.Exchange.TenantAttribution", "Investigate tenant attribution",
            "Original connection attribution may differ from the final gateway or tenant classification.",
            "Correlate the original connection evidence with receiver message trace and the applicable inbound connector.",
            "Confirm the source, attributed tenant and connector for the original delivery.");
        Add("HEADERS.Exchange.HeadersFiltered", "Review cross-premises header handling",
            "Header filtering can change the classification seen by downstream receivers.",
            "Compare the original and received message copies and inspect the responsible send connector's header handling.",
            "Confirm which headers the connector retained or removed using receiver logs and preserved message copies.");
        Add("HEADERS.Spam.Category", "Investigate the receiver's filtering category",
            "A receiver category is a filtering observation, not independent content inspection or a proof of maliciousness.",
            "Review this message in the receiver's trace or security investigation tools, including policy actions, overrides and the preserved original content.",
            "Confirm the final delivery or quarantine action and whether the reported category is corroborated.");
        Add("HEADERS.Spam.Confidence", "Review spam handling and final delivery",
            "The reported spam confidence level needs to be interpreted alongside the receiver's policy and actual disposition.",
            "Inspect the applicable anti-spam policy, overrides and message trace; investigate unexpected delivery without treating the header score as an independent verdict.",
            "Confirm the final action and the policy or override responsible for it.");
        Add("HEADERS.Field.Duplicate", "Resolve ambiguous singleton fields",
            "Different clients can choose different values from duplicated singleton fields.",
            "Preserve all field instances and compare the original MIME message with receiver logs. Check the producer and gateway for duplicate insertion.",
            "Confirm that a fresh message has one unambiguous value for each singleton field.");
        Add("HEADERS.Unicode.DirectionControl", "Inspect concealed display direction",
            "Direction controls can make displayed identities or text differ from their underlying order.",
            "Review the visible code points and underlying addresses in the evidence appendix; compare them with the original MIME message.",
            "Confirm the actual address and domain without relying solely on visually reordered text.");
        Add("HEADERS.Auth.Conflict", "Reconcile conflicting authentication observations",
            "Conflicting results for the same identity prevent a single reliable interpretation.",
            "Compare authentication writers, gateway sanitization and receiver logs. Verify the original MIME message independently when available.",
            "Establish which receiver produced each result and whether it is authoritative for this delivery.");
        Add("HEADERS.Auth.NoConfiguredMatch", "Confirm the expected authentication writer",
            "None of the supplied authentication results matches the configured gateway identifiers.",
            "Compare the configured identifiers with the actual receiving gateway and message trace. Do not expand trust solely to match an unverified header value.",
            "Confirm the exact writer and header sanitization before relying on its authentication claims.");
        Add("HEADERS.Route.Truncated", "Complete the delivery route evidence",
            "The configured hop limit omitted route records, so route interpretation is incomplete.",
            "Retain the original message and rerun with a suitable hop limit within the analysis resource bounds.",
            "Confirm that no Received records remain omitted before drawing a complete-route conclusion.");
        Add("HEADERS.ARC.Structure", "Investigate the incomplete or inconsistent ARC chain",
            "ARC structure problems prevent treating the headers as a complete chain; structure and cryptographic validity are separate.",
            "Review the reported structure issues and compare preserved message copies across forwarders. Verify the original MIME message where available.",
            "Confirm a complete, ordered chain and inspect its separate cryptographic result and sealer trust.");
        foreach (var code in new[] { "HEADERS.DKIM.DuplicateTag", "HEADERS.DKIM.WeakHash", "HEADERS.DKIM.BodyLength", "HEADERS.DKIM.FromUnsigned" }) {
            Add(code, "Review the DKIM signing configuration",
                "The signature metadata raises an ambiguity or signing coverage concern; receiver claims do not resolve it.",
                "Review the specific finding, signing algorithm, repeated tags and signed-header/body coverage. Preserve the original MIME message and verify it before relying on the signature.",
                "Confirm the corrected signer configuration on a fresh message and inspect local cryptographic verification and coverage.");
        }
    }
}
