using System.Collections.Generic;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public sealed class CookieAttributeSummary
    {
        public int TotalFirstParty { get; internal set; }
        public int Secure { get; internal set; }
        public int HttpOnly { get; internal set; }
        public int SameSiteLax { get; internal set; }
        public int SameSiteStrict { get; internal set; }
        public int SameSiteNone { get; internal set; }
        public int SameSiteMissing { get; internal set; }
        public int MaxAgePresent { get; internal set; }
        public int DomainPresent { get; internal set; }
        internal void Clear()
        {
            TotalFirstParty = Secure = HttpOnly = SameSiteLax = SameSiteStrict = SameSiteNone = SameSiteMissing = MaxAgePresent = DomainPresent = 0;
        }
    }

    public sealed class CorsSummary
    {
        public int FirstPartyResponses { get; internal set; }
        public int WildcardOriginCount { get; internal set; }
        public int CredentialsCount { get; internal set; }
        public HashSet<string> Origins { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Methods { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Headers { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        internal void Clear()
        {
            FirstPartyResponses = 0; WildcardOriginCount = 0; CredentialsCount = 0; Origins.Clear(); Methods.Clear(); Headers.Clear();
        }
    }

    public sealed class ServerTimingSummary
    {
        public int FirstPartyResponses { get; internal set; }
        public HashSet<string> Metrics { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        internal void Clear() { FirstPartyResponses = 0; Metrics.Clear(); }
    }
}

