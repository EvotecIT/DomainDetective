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
    }
}
