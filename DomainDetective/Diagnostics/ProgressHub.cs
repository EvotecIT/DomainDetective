using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Subscribes to <see cref="InternalLogger"/> and forwards events to registered <see cref="IProgressSink"/>s.
/// </summary>
public sealed class ProgressHub : IDisposable
{
    private readonly InternalLogger _logger;
    private readonly List<IProgressSink> _sinks = new();
    private bool _disposed;

    /// <summary>Initializes a new instance of the ProgressHub class.</summary>
    public ProgressHub(InternalLogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Attach();
    }

    /// <summary>Adds sink.</summary>
    public void AddSink(IProgressSink sink)
    {
        if (sink == null) return;
        _sinks.Add(sink);
    }

    private void Attach()
    {
        _logger.OnProgressMessage += HandleProgress;
        _logger.OnInformationMessage += HandleInfo;
        _logger.OnWarningMessage += HandleWarn;
        _logger.OnErrorMessage += HandleErr;
        _logger.OnVerboseMessage += HandleVerbose;
        _logger.OnDebugMessage += HandleDebug;
    }

    private void HandleProgress(object? sender, LogEventArgs e)
    {
        foreach (var s in _sinks) { try { s.OnProgress(e); } catch { } }
    }
    private void HandleInfo(object? sender, LogEventArgs e)
    {
        foreach (var s in _sinks) { try { s.OnInformation(e); } catch { } }
    }
    private void HandleWarn(object? sender, LogEventArgs e)
    {
        foreach (var s in _sinks) { try { s.OnWarning(e); } catch { } }
    }
    private void HandleErr(object? sender, LogEventArgs e)
    {
        foreach (var s in _sinks) { try { s.OnError(e); } catch { } }
    }
    private void HandleVerbose(object? sender, LogEventArgs e)
    {
        foreach (var s in _sinks) { try { s.OnVerbose(e); } catch { } }
    }
    private void HandleDebug(object? sender, LogEventArgs e)
    {
        foreach (var s in _sinks) { try { s.OnDebug(e); } catch { } }
    }

    /// <summary>Executes the dispose operation.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try {
            _logger.OnProgressMessage -= HandleProgress;
            _logger.OnInformationMessage -= HandleInfo;
            _logger.OnWarningMessage -= HandleWarn;
            _logger.OnErrorMessage -= HandleErr;
            _logger.OnVerboseMessage -= HandleVerbose;
            _logger.OnDebugMessage -= HandleDebug;
        } catch { }
        foreach (var s in _sinks)
        {
            try { (s as IDisposable)?.Dispose(); } catch { }
        }
        _sinks.Clear();
    }
}

