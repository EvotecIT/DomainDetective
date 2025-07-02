using System;
using System.Collections.Generic;

namespace DomainDetective {
    /// <summary>
    ///     Represents condensed results of domain health checks.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Inspect WHOIS expiration details.</summary>
    ///   <code>
    ///   var health = new DomainHealthCheck();
    ///   await health.Verify("example.com");
    ///   var summary = health.BuildSummary();
    ///   Console.WriteLine(summary.ExpiryDate);
    ///   </code>
    /// </example>
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

        /// <summary>
        /// Indicates whether the analyzed domain is itself a public suffix as
        /// defined by <see href="https://datatracker.ietf.org/doc/html/rfc8499"/>
        /// RFC&nbsp;8499.
        /// </summary>
        public bool IsPublicSuffix { get; init; }

        /// <summary>Expiration date reported by WHOIS.</summary>
        public string ExpiryDate { get; init; }

        /// <summary>True when the domain expires soon.</summary>
        public bool ExpiresSoon { get; init; }

        /// <summary>True when the domain is past its expiration date.</summary>
        public bool IsExpired { get; init; }

        /// <summary>True when registrar lock is enabled.</summary>
        public bool RegistrarLocked { get; init; }

        /// <summary>True when WHOIS data is privacy protected.</summary>
        public bool PrivacyProtected { get; init; }

        /// <summary>Collection of recommended remediation hints.</summary>
        public IReadOnlyList<string> Hints { get; init; } = Array.Empty<string>();
    }
}
