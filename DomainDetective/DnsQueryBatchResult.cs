using System;
using DnsClientX;

namespace DomainDetective;

/// <summary>Represents one DNS query result in a batch operation.</summary>
public sealed class DnsQueryBatchResult
{
    /// <summary>Gets or sets the name value.</summary>
    public string Name { get; init; } = string.Empty;
    /// <summary>Gets or sets the record type value.</summary>
    public DnsRecordType RecordType { get; init; }
    /// <summary>Gets or sets the response code value.</summary>
    public DnsResponseCode ResponseCode { get; init; }
    /// <summary>Gets or sets the answers value.</summary>
    public DnsAnswer[] Answers { get; init; } = Array.Empty<DnsAnswer>();
    /// <summary>Gets or sets the query succeeded value.</summary>
    public bool QuerySucceeded { get; init; }
}

