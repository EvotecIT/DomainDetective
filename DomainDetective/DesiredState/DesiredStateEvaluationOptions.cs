namespace DomainDetective.DesiredState;

/// <summary>
/// Controls exception handling behavior during desired state evaluation.
/// </summary>
public sealed class DesiredStateEvaluationOptions {
    /// <summary>
    /// When true, evaluation rethrows exceptions instead of logging and continuing.
    /// </summary>
    public bool ThrowOnError { get; set; }

    /// <summary>
    /// When true, evaluation logs exceptions as errors instead of warnings.
    /// </summary>
    public bool LogExceptionsAsErrors { get; set; }
}
