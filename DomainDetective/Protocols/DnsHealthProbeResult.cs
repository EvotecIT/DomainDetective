using DnsClientX;
using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Distinguishes a supported comparison from missing evidence.</summary>
public enum DnsHealthConsistencyStatus {
    /// <summary>Fewer than two complete endpoints or incomplete coverage.</summary>
    InsufficientEvidence,
    /// <summary>All expected endpoints supplied matching evidence.</summary>
    Consistent,
    /// <summary>Observed authoritative endpoints supplied different evidence.</summary>
    Inconsistent
}

/// <summary>Records one authoritative probe, including NODATA, DNS errors and unanswered requests.</summary>
public sealed class DnsHealthProbeResult {
    /// <summary>Gets the target address.</summary>
    public string ServerAddress { get; internal set; } = string.Empty;
    /// <summary>Gets nameservers attributed to the address.</summary>
    public IReadOnlyList<string> NameServers { get; internal set; } = Array.Empty<string>();
    /// <summary>Gets the requested record type.</summary>
    public DnsRecordType RecordType { get; internal set; }
    /// <summary>True when the probe entered its transport; false when the budget prevented dispatch.</summary>
    public bool Attempted { get; internal set; }
    /// <summary>Gets the DNS response code, or null when no response was received.</summary>
    public DnsResponseCode? ResponseCode { get; internal set; }
    /// <summary>Gets whether the response carries the authoritative-answer flag.</summary>
    public bool IsAuthoritative { get; internal set; }
    /// <summary>Gets whether any DNS response was received.</summary>
    public bool HasResponse => ResponseCode.HasValue;
    /// <summary>Gets whether the server returned NoError without a transport/parser error.</summary>
    public bool ResponseSucceeded => ResponseCode == DnsResponseCode.NoError && string.IsNullOrEmpty(Error);
    /// <summary>Gets matching answer records. A successful empty set is NODATA.</summary>
    public IReadOnlyList<DnsAnswer> Answers { get; internal set; } = Array.Empty<DnsAnswer>();
    /// <summary>Gets the failure or budget diagnostic.</summary>
    public string? Error { get; internal set; }
    /// <summary>Gets elapsed probe time, including fallback and transport cleanup.</summary>
    public long ElapsedMilliseconds { get; internal set; }
}
