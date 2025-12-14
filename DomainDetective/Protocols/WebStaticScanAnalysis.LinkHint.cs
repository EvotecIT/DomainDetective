namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public sealed class LinkHint
    {
        public string Rel { get; set; } = null!;
        public string Href { get; set; } = null!;
        public string? Host { get; set; }
        public bool FirstParty { get; set; }
    }
}

