using System;
using System.Collections.Generic;

namespace DomainDetective;

public partial class HttpAnalysis {
    private void ResetResults() {
        StatusCode = null;
        ResponseTime = TimeSpan.Zero;
        IsReachable = false;
        Http2Supported = false;
        Http3Supported = false;
        HstsPresent = false;
        BodyTruncated = false;
        RequestMethodUsed = HttpRequestMethod.Get;
        TlsValidationDisabled = false;
        ProxyUsed = null;
        Assessments.Clear();
        FailureReason = null;
        ProtocolVersion = null;
        Body = null; BodyLength = null; BodySha256 = null; NelRaw = null; ReportToRaw = null; SpeculationRulesRaw = null;
        ServerHeader = null;
        VisitedUrls.Clear();
        RequestHeaderNames.Clear();
        InformationDisclosureHeaders.Clear();
        CachingHeaders.Clear();
        DeprecatedHeadersPresent.Clear();
        MissingDeprecatedHeaders.Clear();
        MixedContentDetected = false;
        InsecureFormsCount = 0;
        InsecureFormActions.Clear();
        XssProtectionPresent = false;
        ExpectCtPresent = false;
        ExpectCtMaxAge = null;
        ExpectCtReportUri = null;
#pragma warning disable CS0618
        PublicKeyPinsPresent = false;
#pragma warning restore CS0618
        CspUnsafeDirectives = false;
        HstsMaxAge = null;
        HstsIncludesSubDomains = false;
        HstsTooShort = false;
        HstsPreloaded = false;
        HstsPreloadDirectivePresent = false;
        HstsPreloadEligible = false;
        UnknownHstsDirectives = new List<string>();
        PermissionsPolicyPresent = false;
        PermissionsPolicy.Clear();
        QuicVersion = null;
        ReferrerPolicy = null;
        XFrameOptions = null;
        CrossOriginOpenerPolicy = null;
        CrossOriginEmbedderPolicy = null;
        CrossOriginResourcePolicy = null;
        XPermittedCrossDomainPolicies = null;
        OriginAgentClusterPresent = false;
        OriginAgentClusterEnabled = false;
        CspFrameAncestorsPresent = false;
        SecurityHeaders.Clear();
        MissingSecurityHeaders.Clear();
    }
}
