namespace DomainDetective;

/// <summary>
/// Receives progress and message events for a run. Implementations may write to console, files, or UIs.
/// </summary>
public interface IProgressSink
{
    /// <summary>Executes the on progress operation.</summary>
    void OnProgress(LogEventArgs e);
    /// <summary>Executes the on information operation.</summary>
    void OnInformation(LogEventArgs e);
    /// <summary>Executes the on warning operation.</summary>
    void OnWarning(LogEventArgs e);
    /// <summary>Executes the on error operation.</summary>
    void OnError(LogEventArgs e);
    /// <summary>Executes the on verbose operation.</summary>
    void OnVerbose(LogEventArgs e);
    /// <summary>Executes the on debug operation.</summary>
    void OnDebug(LogEventArgs e);
}

