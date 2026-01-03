using System;
using DnsClientX;

namespace DomainDetective;

/// <summary>Represents one DNS query result in a batch operation.</summary>
public sealed class DnsQueryBatchResult
{
    public string Name { get; init; } = string.Empty;
    public DnsRecordType RecordType { get; init; }
    public DnsResponseCode ResponseCode { get; init; }
    public DnsAnswer[] Answers { get; init; } = Array.Empty<DnsAnswer>();
    public bool QuerySucceeded { get; init; }
}

