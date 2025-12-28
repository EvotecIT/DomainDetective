namespace DomainDetective;

/// <summary>
/// Provides execution configuration helpers for <see cref="DomainHealthCheck"/>.
/// </summary>
public partial class DomainHealthCheck {
    /// <summary>
    /// Applies execution options to resolver concurrency and logging behavior.
    /// </summary>
    /// <param name="executionOptions">Optional settings to apply for this run.</param>
    public void ConfigureExecution(HealthCheckExecutionOptions? executionOptions = null) {
        var options = executionOptions ?? ExecutionOptions;
        if (options.ResetLogDedupOnRun) {
            _logger.ClearLoggedMessages();
        }
        ApplyExecutionOptions(options);
    }
}
