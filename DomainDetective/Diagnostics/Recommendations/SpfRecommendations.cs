using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SpfRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SpfCodes.LookupsExceeded] = new RecommendationAdvice {
            Code = SpfCodes.LookupsExceeded,
            Title = "SPF exceeds 10-DNS-lookup limit",
            Why = "SPF processing stops with permerror when more than 10 DNS mechanisms lookups are required.",
            How = "Reduce include/redirect mechanisms, collapse IP ranges, and use flattening with TTL-aware automation to stay ≤10 lookups.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "dns" },
            Impact = "Receivers may permerror and fail SPF, hurting deliverability.",
            Effort = RecommendationEffort.Medium,
            Verify = "Evaluate SPF with an online tester; ensure ≤10 DNS lookups."
        };

        map[SpfCodes.IncludeCycle] = new RecommendationAdvice {
            Code = SpfCodes.IncludeCycle,
            Title = "SPF include cycle detected",
            Why = "Cyclic includes prevent reliable SPF evaluation and can cause permerrors at receivers.",
            How = "Remove cyclic include chains; audit third-party includes and replace with static IPs or a single known-good include.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf" },
            Impact = "SPF checks may fail sporadically across receivers.",
            Effort = RecommendationEffort.Medium,
            Verify = "Trace include chain; confirm no cycles remain."
        };

        map[SpfCodes.FlattenedLengthExceeds512] = new RecommendationAdvice {
            Code = SpfCodes.FlattenedLengthExceeds512,
            Title = "Flattened SPF record exceeds 512 bytes",
            Why = "Large TXT responses may be truncated over UDP, causing receivers to fail SPF checks.",
            How = "Shorten the record: remove unused mechanisms, de-duplicate IPs, and split across multiple include domains with minimal content.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf" },
            Impact = "Truncated DNS responses lead to failures or timeouts.",
            Effort = RecommendationEffort.Medium,
            Verify = "Check TXT response size and TC bit; prefer ≤512 bytes or ensure TCP fallback works."
        };

        map[SpfCodes.FlattenedLengthExceeds255] = new RecommendationAdvice {
            Code = SpfCodes.FlattenedLengthExceeds255,
            Title = "An SPF TXT chunk exceeds 255 chars",
            Why = "DNS TXT strings are limited to 255 bytes per chunk; longer parts are invalid and can break parsing.",
            How = "Split the TXT into multiple quoted chunks or reduce content; ensure each chunk ≤255 bytes.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-3.3" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "dns" },
            Impact = "Invalid record parsing at receivers.",
            Effort = RecommendationEffort.Low,
            Verify = "Use dig/NSLookup to confirm each TXT chunk ≤255 bytes."
        };

        map[SpfCodes.TxtChunkTooLong] = new RecommendationAdvice {
            Code = SpfCodes.TxtChunkTooLong,
            Title = "SPF TXT part exceeds 255 bytes",
            Why = "Exceeding 255 bytes in a single TXT chunk is not RFC-compliant and breaks SPF parsing.",
            How = "Split long strings into multiple quoted chunks or simplify mechanisms.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "dns" }
        };

        map[SpfCodes.MacroSyntaxInvalid] = new RecommendationAdvice {
            Code = SpfCodes.MacroSyntaxInvalid,
            Title = "Invalid SPF macro syntax",
            Why = "Malformed SPF macros can cause receivers to error when evaluating the policy.",
            How = "Correct macro syntax per RFC 7208 or avoid macros entirely; prefer explicit IPs.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-7" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf" },
            Impact = "Evaluation errors and inconsistent results across receivers.",
            Effort = RecommendationEffort.Low,
            Verify = "Lint SPF macros using a validator and unit tests for representative senders."
        };

        map[SpfCodes.MacroPercentInvalid] = new RecommendationAdvice {
            Code = SpfCodes.MacroPercentInvalid,
            Title = "Invalid percent escape in SPF macro",
            Why = "Incorrect percent-encoding breaks macro evaluation and may produce permerror.",
            How = "Use correct percent escapes (e.g., %{}%_), or remove macro usage.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-7.1" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf" },
            Impact = "Receivers may treat the record as permerror.",
            Effort = RecommendationEffort.Low,
            Verify = "Validate resulting macro expansions and ensure encodings are correct."
        };
        map[SpfCodes.MissingRecord] = new RecommendationAdvice {
            Code = SpfCodes.MissingRecord,
            Title = "Publish an SPF record",
            Why = "Without SPF, receivers cannot verify authorized senders, harming deliverability and spoofing resistance.",
            How = "Add a TXT record at the apex with v=spf1 and authorized mechanisms; keep lookups ≤10 and end with -all.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "dns" },
            Impact = "Increased spoofing risk and reduced mail acceptance.",
            Effort = RecommendationEffort.Medium,
            Verify = "dig TXT example.com shows a single v=spf1 policy."
        };
        map[SpfCodes.MultipleRecords] = new RecommendationAdvice {
            Code = SpfCodes.MultipleRecords,
            Title = "Consolidate multiple SPF records into one",
            Why = "Multiple SPF records make evaluation undefined and can cause permerrors.",
            How = "Merge mechanisms into a single v=spf1 string; use include where needed; remove duplicates.",
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf" },
            Impact = "Receivers may fail SPF evaluation.",
            Effort = RecommendationEffort.Low,
            Verify = "Only one TXT with v=spf1 remains."
        };
        map[SpfCodes.StartsInvalid] = new RecommendationAdvice {
            Code = SpfCodes.StartsInvalid,
            Title = "Fix SPF version tag",
            Why = "SPF records must begin with v=spf1 to be recognized.",
            How = "Ensure the record starts with v=spf1 and contains only valid mechanisms/modifiers.",
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf" },
            Impact = "Policy ignored by receivers.",
            Effort = RecommendationEffort.Low,
            Verify = "Record starts with v=spf1."
        };
        map[SpfCodes.RecordLengthExceeds] = new RecommendationAdvice {
            Code = SpfCodes.RecordLengthExceeds,
            Title = "Reduce SPF record size",
            Why = "Oversized records risk UDP truncation and parsing issues.",
            How = "Remove unused mechanisms, split chunks to ≤255 chars, and keep flattened size ≤512 bytes.",
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "dns" },
            Impact = "Receivers may fail SPF checks due to truncation.",
            Effort = RecommendationEffort.Medium,
            Verify = "TXT response size fits typical UDP limits; no TC bit."
        };

        map[SpfCodes.QueryFailed] = new RecommendationAdvice {
            Code = SpfCodes.QueryFailed,
            Title = "SPF DNS query failed",
            Why = "Transient DNS or HTTP issues can prevent fetching SPF TXT records, leading to flaky evaluations.",
            How = "Retry with a different resolver or increase timeout; ensure network egress and DNS over HTTPS endpoints are reachable.",
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "dns", "availability" },
            Impact = "SPF validation may be skipped by tooling; receivers may still succeed.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-run lookup; confirm TXT v=spf1 is retrievable."
        };

        map[SpfCodes.AllSoft] = new RecommendationAdvice {
            Code = SpfCodes.AllSoft,
            Title = "Strengthen SPF policy to -all",
            Why = "Softfail/neutral (~all/?all) do not enforce rejection and allow spoof attempts to be accepted more easily.",
            How = "After validating legitimate senders, switch to '-all' for enforcement. Coordinate with DMARC so alignment continues to pass.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-5.1" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "policy" },
            Impact = "Improves spoof resistance at receivers that evaluate SPF strictly.",
            Effort = RecommendationEffort.Low,
            Verify = "Mail from authorized IPs passes; unauthorized sources fail with -all."
        };

        map[SpfCodes.AllMissing] = new RecommendationAdvice {
            Code = SpfCodes.AllMissing,
            Title = "Add final -all mechanism",
            Why = "A terminating '-all' clarifies policy and signals that only listed sources are authorized.",
            How = "Append '-all' to the end of the SPF record once all sources are listed and validated.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-4.6.2" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "policy" },
            Impact = "Prevents ambiguous evaluation and reduces spoof acceptance.",
            Effort = RecommendationEffort.Low,
            Verify = "SPF terminates with '-all' and tests show expected failures for unauthorized senders."
        };

        map[SpfCodes.AllMultiple] = new RecommendationAdvice {
            Code = SpfCodes.AllMultiple,
            Title = "Remove duplicate 'all' mechanisms",
            Why = "Only the last 'all' is effective; earlier ones are ignored and add noise and size.",
            How = "Keep a single 'all' at the end of the record; remove extras.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-4.7" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf" },
            Impact = "Simplifies policy and reduces risk of misinterpretation.",
            Effort = RecommendationEffort.Low,
            Verify = "Record contains exactly one 'all' as the last mechanism."
        };

        map[SpfCodes.AllTrailingContent] = new RecommendationAdvice {
            Code = SpfCodes.AllTrailingContent,
            Title = "Remove mechanisms after 'all'",
            Why = "Mechanisms after 'all' are never evaluated and only increase record size.",
            How = "Reorder or remove trailing mechanisms; ensure 'all' remains last.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-4.7" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf" },
            Impact = "Avoids confusion and reduces DNS payload size.",
            Effort = RecommendationEffort.Low,
            Verify = "'all' is last; no trailing tokens after it."
        };

        map[SpfCodes.PtrUsed] = new RecommendationAdvice {
            Code = SpfCodes.PtrUsed,
            Title = "Avoid PTR mechanism in SPF",
            Why = "'ptr' is slow, unreliable, and discouraged by RFC 7208 due to operational and privacy issues.",
            How = "Replace 'ptr' with explicit ip4/ip6 ranges or a/mx mechanisms where appropriate.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-5.5" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "ptr" },
            Impact = "Reduces DNS load and evaluation variability.",
            Effort = RecommendationEffort.Medium,
            Verify = "No 'ptr:' tokens remain; evaluation time decreases."
        };

        map[SpfCodes.ExistsUsed] = new RecommendationAdvice {
            Code = SpfCodes.ExistsUsed,
            Title = "Use 'exists' sparingly",
            Why = "'exists' performs custom DNS lookups which can be expensive and unpredictable.",
            How = "Prefer explicit ip4/ip6 or a/mx mechanisms; limit 'exists' to necessary cases.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7208#section-5.7" },
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "dns" },
            Impact = "Improves reliability and performance of SPF evaluation.",
            Effort = RecommendationEffort.Low,
            Verify = "Record contains minimal or no 'exists:' tokens."
        };

        // Presence/positive signals
        map[SpfCodes.IncludeChainValid] = new RecommendationAdvice {
            Code = SpfCodes.IncludeChainValid,
            Title = "SPF include chain resolves cleanly",
            Why = "All include/redirect mechanisms resolved without loops, ensuring dependable policy evaluation.",
            How = "Keep third-party include targets stable and monitor for DNS changes or deprecations.",
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "dns" },
            Impact = "Improves reliability of SPF processing.",
            Effort = RecommendationEffort.Low,
            Verify = "Include and redirect lookups succeed with no cycles."
        };

        map[SpfCodes.LookupsWithinLimit] = new RecommendationAdvice {
            Code = SpfCodes.LookupsWithinLimit,
            Title = "SPF DNS lookups within limit",
            Why = "Staying under the 10-lookup cap avoids permerrors and speeds evaluation.",
            How = "Continue using flattened includes and consolidated mechanisms to keep lookups minimal.",
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "dns" },
            Impact = "Ensures receivers can evaluate the record efficiently.",
            Effort = RecommendationEffort.Low,
            Verify = "DNS lookups remain under 10."
        };

        map[SpfCodes.AllEnforced] = new RecommendationAdvice {
            Code = SpfCodes.AllEnforced,
            Title = "SPF policy aligned and enforced",
            Why = "A terminating '-all' rejects unauthorized senders and aligns with strict DMARC policy.",
            How = "Maintain '-all' after confirming all legitimate sources are authorized.",
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "policy" },
            Impact = "Reduces spoofing and supports DMARC alignment.",
            Effort = RecommendationEffort.Low,
            Verify = "Record ends with '-all' and passes DMARC alignment tests."
        };
    }
}
