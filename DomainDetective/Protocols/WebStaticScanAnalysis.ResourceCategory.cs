namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public enum ResourceCategory
    {
        Other = 0,
        Document,
        Stylesheet,
        Script,
        Image,
        Font,
        Json
    }
}

