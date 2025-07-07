namespace DomainDetective {
    /// <summary>
    /// Provider specific reply code configuration.
    /// </summary>
    public class DnsblReplyCode {
        /// <summary>
        /// Indicates whether the returned code means the host is listed.
        /// </summary>
        public bool IsListed { get; set; }

        /// <summary>
        /// Human readable explanation of the reply code.
        /// </summary>
        public string Meaning { get; set; }
    }
}
