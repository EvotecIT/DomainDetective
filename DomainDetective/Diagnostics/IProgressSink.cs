namespace DomainDetective;

/// <summary>
/// Receives progress and message events for a run. Implementations may write to console, files, or UIs.
/// </summary>
public interface IProgressSink
{
    void OnProgress(LogEventArgs e);
    void OnInformation(LogEventArgs e);
    void OnWarning(LogEventArgs e);
    void OnError(LogEventArgs e);
    void OnVerbose(LogEventArgs e);
    void OnDebug(LogEventArgs e);
}

