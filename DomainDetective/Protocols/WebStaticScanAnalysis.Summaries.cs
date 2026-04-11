using System.Collections.Generic;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>Provides cookie attribute summary functionality.</summary>
    public sealed class CookieAttributeSummary
    {
        /// <summary>Gets or sets the total first party value.</summary>
        public int TotalFirstParty { get; internal set; }
        /// <summary>Gets or sets the secure value.</summary>
        public int Secure { get; internal set; }
        /// <summary>Gets or sets the http only value.</summary>
        public int HttpOnly { get; internal set; }
        /// <summary>Gets or sets the same site lax value.</summary>
        public int SameSiteLax { get; internal set; }
        /// <summary>Gets or sets the same site strict value.</summary>
        public int SameSiteStrict { get; internal set; }
        /// <summary>Gets or sets the same site none value.</summary>
        public int SameSiteNone { get; internal set; }
        /// <summary>Gets or sets the same site missing value.</summary>
        public int SameSiteMissing { get; internal set; }
        /// <summary>Gets or sets the max age present value.</summary>
        public int MaxAgePresent { get; internal set; }
        /// <summary>Gets or sets the domain present value.</summary>
        public int DomainPresent { get; internal set; }
        internal void Clear()
        {
            TotalFirstParty = Secure = HttpOnly = SameSiteLax = SameSiteStrict = SameSiteNone = SameSiteMissing = MaxAgePresent = DomainPresent = 0;
        }
    }

    /// <summary>Provides cors summary functionality.</summary>
    public sealed class CorsSummary
    {
        /// <summary>Gets or sets the first party responses value.</summary>
        public int FirstPartyResponses { get; internal set; }
        /// <summary>Gets or sets the wildcard origin count value.</summary>
        public int WildcardOriginCount { get; internal set; }
        /// <summary>Gets or sets the credentials count value.</summary>
        public int CredentialsCount { get; internal set; }
        /// <summary>Gets the origins value.</summary>
        public HashSet<string> Origins { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets the methods value.</summary>
        public HashSet<string> Methods { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets the headers value.</summary>
        public HashSet<string> Headers { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        internal void Clear()
        {
            FirstPartyResponses = 0; WildcardOriginCount = 0; CredentialsCount = 0; Origins.Clear(); Methods.Clear(); Headers.Clear();
        }
    }

    /// <summary>Provides server timing summary functionality.</summary>
    public sealed class ServerTimingSummary
    {
        /// <summary>Gets or sets the first party responses value.</summary>
        public int FirstPartyResponses { get; internal set; }
        /// <summary>Gets the metrics value.</summary>
        public HashSet<string> Metrics { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        internal void Clear() { FirstPartyResponses = 0; Metrics.Clear(); }
    }
}

