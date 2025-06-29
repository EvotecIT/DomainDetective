namespace DomainDetective {
    /// <summary>
    /// Provider specific reply code configuration.
    /// </summary>
    public class DnsblReplyCode {
        public bool IsListed { get; set; }
        public string Meaning { get; set; }
    }
}
