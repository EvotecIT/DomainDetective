using System;

namespace DomainDetective;

public class UnsupportedTldException : Exception
{
    public string Domain { get; }
    public string Tld { get; }

    public UnsupportedTldException(string domain, string tld) : base($"TLD '{tld}' is not supported for WHOIS lookup.")
    {
        Domain = domain;
        Tld = tld;
    }
}
