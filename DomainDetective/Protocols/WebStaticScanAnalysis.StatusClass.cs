namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// HTTP status code family classification.
    /// </summary>
    public enum StatusClass
    {
        /// <summary>Undefined or not applicable.</summary>
        None = 0,
        /// <summary>1xx informational responses.</summary>
        Informational = 1,
        /// <summary>2xx successful responses.</summary>
        Success = 2,
        /// <summary>3xx redirection responses.</summary>
        Redirection = 3,
        /// <summary>4xx client error responses.</summary>
        ClientError = 4,
        /// <summary>5xx server error responses.</summary>
        ServerError = 5
    }
}

