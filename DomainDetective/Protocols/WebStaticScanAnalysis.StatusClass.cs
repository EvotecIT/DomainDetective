namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public enum StatusClass
    {
        None = 0,
        Informational = 1,
        Success = 2,
        Redirection = 3,
        ClientError = 4,
        ServerError = 5
    }
}

