using DnsClientX;
using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Retains nameserver and address discovery evidence separately from authoritative probes.</summary>
public sealed class DnsHealthDiscoveryResult {
    /// <summary>Gets the queried name.</summary>
    public string Name { get; internal set; } = string.Empty;
    /// <summary>Gets the requested record type.</summary>
    public DnsRecordType RecordType { get; internal set; }
    /// <summary>Gets the response code, or null when discovery did not return a response.</summary>
    public DnsResponseCode? ResponseCode { get; internal set; }
    /// <summary>Gets matching answer records, including a successful empty NODATA set.</summary>
    public IReadOnlyList<DnsAnswer> Answers { get; internal set; } = Array.Empty<DnsAnswer>();
    /// <summary>Gets the discovery failure or budget diagnostic.</summary>
    public string? Error { get; internal set; }
    /// <summary>True when discovery completed successfully, including NODATA.</summary>
    public bool Succeeded => ResponseCode == DnsResponseCode.NoError && string.IsNullOrEmpty(Error);
}
