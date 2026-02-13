using System;

namespace DomainDetective;

/// <summary>Timing details for email validation.</summary>
public sealed class EmailAddressValidationDebug {
    public DateTimeOffset StartTime { get; set; }
    public DateTimeOffset EndTime { get; set; }
    public TimeSpan Duration { get; set; }
}
