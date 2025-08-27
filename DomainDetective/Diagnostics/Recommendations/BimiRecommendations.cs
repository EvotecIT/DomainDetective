using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class BimiRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[BimiCodes.MissingRecord] = new RecommendationAdvice {
            Code = BimiCodes.MissingRecord,
            Title = "Publish a BIMI record",
            Why = "Without BIMI, supported receivers will not display your brand logo.",
            How = "Add a TXT at default._bimi.example.com with v=BIMI1; l=https://.../logo.svg; optionally a=https://.../vmc.pem.",
            Links = new [] { "https://bimigroup.org/" },
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "bimi", "dns" },
            Impact = "No brand indicator in inboxes.",
            Effort = RecommendationEffort.Low,
            Verify = "dig TXT default._bimi.example.com returns a v=BIMI1 record."
        };

        map[BimiCodes.StartsInvalid] = new RecommendationAdvice {
            Code = BimiCodes.StartsInvalid,
            Title = "Fix BIMI version tag",
            Why = "BIMI records must begin with v=BIMI1 to be recognized.",
            How = "Ensure the TXT starts with v=BIMI1 and includes 'l=' (and optionally 'a=').",
            Links = new [] { "https://bimigroup.org/" },
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "bimi" },
            Impact = "Record ignored by receivers.",
            Effort = RecommendationEffort.Low,
            Verify = "Record starts with v=BIMI1."
        };
        map[BimiCodes.InvalidLocation] = new RecommendationAdvice {
            Code = BimiCodes.InvalidLocation,
            Title = "Invalid BIMI location",
            Why = "Receivers cannot retrieve the BIMI indicator; brand logo will not display.",
            How = "Publish 'l=' URL pointing to a valid SVG (or SVGZ) over HTTPS.",
            Links = new [] { "https://bimigroup.org/" },
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "bimi" },
            Impact = "Brand indicators are suppressed in inboxes.",
            Effort = RecommendationEffort.Low,
            Verify = "Check BIMI TXT 'l=' is https and ends with .svg/.svgz."
        };

        map[BimiCodes.LocationNotHttps] = new RecommendationAdvice {
            Code = BimiCodes.LocationNotHttps,
            Title = "BIMI indicator must be served over HTTPS",
            Why = "HTTP indicators are rejected by receivers for security reasons.",
            How = "Host the BIMI SVG at an HTTPS URL with a valid certificate.",
            Links = new [] { "https://bimigroup.org/" },
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "bimi", "https" },
            Impact = "Logo will not be shown.",
            Effort = RecommendationEffort.Low,
            Verify = "Fetch indicator URL via HTTPS; confirm 200 and correct MIME."
        };

        map[BimiCodes.InvalidMimeType] = new RecommendationAdvice {
            Code = BimiCodes.InvalidMimeType,
            Title = "Invalid BIMI indicator MIME type",
            Why = "Receivers expect image/svg+xml (or gzip variant). Incorrect types are rejected.",
            How = "Serve the indicator as 'image/svg+xml' or 'image/svg+xml; charset=utf-8'.",
            Links = new [] { "https://bimigroup.org/" },
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "bimi", "svg" },
            Impact = "Logo rejected by receivers.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect Content-Type of indicator response."
        };

        map[BimiCodes.SvgTooLarge] = new RecommendationAdvice {
            Code = BimiCodes.SvgTooLarge,
            Title = "BIMI SVG exceeds 32 KB",
            Why = "Large indicators are rejected by receivers.",
            How = "Optimize SVG; remove metadata/whitespace; consider simplified paths to reduce size.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/draft-ietf-bimi-group-00" },
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "bimi", "svg" },
            Impact = "Logo not displayed.",
            Effort = RecommendationEffort.Medium,
            Verify = "Check file size ≤ 32768 bytes."
        };

        map[BimiCodes.SvgMissingAttributes] = new RecommendationAdvice {
            Code = BimiCodes.SvgMissingAttributes,
            Title = "BIMI SVG missing required attributes",
            Why = "Missing width/height/viewBox can cause incorrect rendering or rejection.",
            How = "Provide explicit width/height and a square viewBox; ensure 1:1 scaling.",
            Links = new [] { "https://bimigroup.org/" },
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "bimi", "svg" },
            Impact = "Logo may render incorrectly or be rejected.",
            Effort = RecommendationEffort.Low,
            Verify = "Open SVG and confirm width/height/viewBox present and square."
        };

        map[BimiCodes.SvgWrongDimensions] = new RecommendationAdvice {
            Code = BimiCodes.SvgWrongDimensions,
            Title = "BIMI SVG should be square",
            Why = "Non-square indicators may be cropped or rejected.",
            How = "Use equal width and height and a square viewBox (e.g., 0 0 100 100).",
            Links = new [] { "https://bimigroup.org/" },
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "bimi", "svg" },
            Impact = "Inconsistent rendering across clients.",
            Effort = RecommendationEffort.Low,
            Verify = "Validate width == height and viewBox square."
        };
    }
}
