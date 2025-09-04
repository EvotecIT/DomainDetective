namespace DomainDetective {
/// <summary>
/// Provider specific reply code configuration.
/// </summary>
/// <remarks>
/// Some providers return custom numeric codes where the meaning is not
/// standardized; this class records whether such codes indicate a listing
/// and provides a textual explanation.
/// </remarks>
public class DnsblReplyCode {
        /// <summary>
        /// Indicates whether the returned code means the host is listed.
        /// </summary>
        public bool IsListed { get; set; }

        /// <summary>
        /// Human readable explanation of the reply code.
        /// </summary>
        public string Meaning { get; set; } = string.Empty;
    }
}
