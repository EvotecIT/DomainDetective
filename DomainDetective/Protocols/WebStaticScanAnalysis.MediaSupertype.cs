namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// High-level classification of media types derived from Content-Type.
    /// </summary>
    public enum MediaSupertype
    {
        /// <summary>Unknown or unspecified.</summary>
        Unknown = 0,
        /// <summary>Textual content (e.g., text/html, text/plain).</summary>
        Text,
        /// <summary>Image content (e.g., image/png, image/jpeg).</summary>
        Image,
        /// <summary>Audio content.</summary>
        Audio,
        /// <summary>Video content.</summary>
        Video,
        /// <summary>Application data (e.g., application/json, application/javascript).</summary>
        Application,
        /// <summary>Multipart content.</summary>
        Multipart
    }
}

