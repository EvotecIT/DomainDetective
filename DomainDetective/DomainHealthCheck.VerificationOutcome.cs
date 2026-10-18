using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public partial class DomainHealthCheck {
    private readonly ConcurrentDictionary<HealthCheckType, byte> _completedVerificationChecks = new();

    /// <summary>
    /// Whether the latest admitted Verify invocation returned every requested check and owned auxiliary phase normally.
    /// Null means no invocation has run. Individual checks can still contain incomplete network evidence after normal completion.
    /// </summary>
    public bool? VerificationCompleted { get; private set; }

    /// <summary>The latest Verify failure or cancellation message, retained alongside partial analysis results; null after a successful run.</summary>
    public string? VerificationError { get; private set; }

    /// <summary>Whether the latest admitted Verify completed its optional plain HTTP phase; null when that phase was not requested.</summary>
    public bool? VerificationPlainHttpCompleted { get; private set; }

    /// <summary>Whether the latest admitted Verify completed its optional takeover phase; null when that phase was not requested.</summary>
    public bool? VerificationTakeoverCompleted { get; private set; }

    /// <summary>The accepted check plan for the latest admitted Verify invocation.</summary>
    public IReadOnlyList<HealthCheckType> VerificationRequestedChecks { get; private set; } = Array.Empty<HealthCheckType>();

    /// <summary>Checks that completed normally in the latest Verify invocation, including shared prerequisites retained after a sibling failure.</summary>
    public IReadOnlyList<HealthCheckType> VerificationCompletedChecks => _completedVerificationChecks.Keys.OrderBy(type => type).ToArray();
}
