using System.Linq;

namespace DomainDetective;

public partial class HttpAnalysis {
    /// <summary>Copies observed HTTP evidence without sharing mutable result containers with a later source run.</summary>
    internal HttpAnalysis CloneForSnapshot() {
        var clone = (HttpAnalysis)MemberwiseClone();
        clone.UnknownHstsDirectives = new(UnknownHstsDirectives);
        clone.SecurityHeaders = new(SecurityHeaders, SecurityHeaders.Comparer);
        clone.MissingSecurityHeaders = new(MissingSecurityHeaders, MissingSecurityHeaders.Comparer);
        clone.InsecureFormActions = new(InsecureFormActions);
        clone.PermissionsPolicy = new(PermissionsPolicy, PermissionsPolicy.Comparer);
        clone.VisitedUrls = new(VisitedUrls);
        clone.RequestHeaderNames = new(RequestHeaderNames);
        clone.InformationDisclosureHeaders = new(InformationDisclosureHeaders, InformationDisclosureHeaders.Comparer);
        clone.CachingHeaders = new(CachingHeaders, CachingHeaders.Comparer);
        clone.DeprecatedHeadersPresent = new(DeprecatedHeadersPresent, DeprecatedHeadersPresent.Comparer);
        clone.MissingDeprecatedHeaders = new(MissingDeprecatedHeaders, MissingDeprecatedHeaders.Comparer);
        clone.Assessments = Assessments.Select(item => item.CloneForSnapshot()).ToList();
        return clone;
    }
}
