namespace DomainDetective {
    /// <summary>
    ///     Represents condensed results of domain health checks.
    /// </summary>
    public class DomainSummary {
        /// <summary>Indicates whether the domain has an SPF record.</summary>
        public bool HasSpfRecord { get; init; }

        /// <summary>Indicates whether the SPF record appears valid.</summary>
        public bool SpfValid { get; init; }

        /// <summary>Indicates whether the domain has a DMARC record.</summary>
        public bool HasDmarcRecord { get; init; }

        /// <summary>Policy configured in the DMARC record.</summary>
        public string DmarcPolicy { get; init; }

        /// <summary>True when the DMARC record appears valid.</summary>
        public bool DmarcValid { get; init; }

        /// <summary>Indicates whether a DKIM record exists.</summary>
        public bool HasDkimRecord { get; init; }

        /// <summary>True when at least one DKIM record appears valid.</summary>
        public bool DkimValid { get; init; }

        /// <summary>Indicates whether MX records exist.</summary>
        public bool HasMxRecord { get; init; }

        /// <summary>True when DNSSEC validation succeeded.</summary>
        public bool DnsSecValid { get; init; }
    }
}
