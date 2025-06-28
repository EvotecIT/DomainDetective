using System;

namespace DomainDetective;

/// <summary>
/// Exception thrown when a TLD is not supported for WHOIS lookups.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class UnsupportedTldException : Exception {
    /// <summary>Gets the domain that was queried.</summary>
    public string Domain { get; }
    /// <summary>Gets the unsupported top-level domain.</summary>
    public string Tld { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="UnsupportedTldException"/> class.
    /// </summary>
    /// <param name="domain">The domain name.</param>
    /// <param name="tld">The unsupported TLD.</param>
    public UnsupportedTldException(string domain, string tld) : base($"TLD '{tld}' is not supported for WHOIS lookup.") {
        Domain = domain;
        Tld = tld;
    }
}