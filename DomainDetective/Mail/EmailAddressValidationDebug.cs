using System;

namespace DomainDetective;

/// <summary>Timing details for email validation.</summary>
public sealed class EmailAddressValidationDebug {
    /// <summary>Gets or sets the start time value.</summary>
    public DateTimeOffset StartTime { get; set; }
    /// <summary>Gets or sets the end time value.</summary>
    public DateTimeOffset EndTime { get; set; }
    /// <summary>Gets or sets the duration value.</summary>
    public TimeSpan Duration { get; set; }
}
