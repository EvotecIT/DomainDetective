using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace DomainDetective.Reports.Artifacts;

/// <summary>
/// Writes log and progress events as JSON Lines (JSONL) to a file.
/// Attach via ProgressHub to receive InternalLogger events.
/// </summary>
public sealed class JsonlProgressSink : IProgressSink, IDisposable
{
    private readonly StreamWriter _writer;
    private bool _disposed;

    public JsonlProgressSink(string filePath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(filePath) ?? ".");
        _writer = new StreamWriter(filePath, append: true, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    public void OnProgress(LogEventArgs e)
    {
        var obj = new {
            ts = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture),
            kind = "progress",
            activity = e.ProgressActivity,
            operation = e.ProgressCurrentOperation,
            percent = e.ProgressPercentage,
            step = e.ProgressCurrentSteps,
            total = e.ProgressTotalSteps
        };
        Write(obj);
    }

    public void OnInformation(LogEventArgs e)
    {
        var obj = new { ts = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), kind = "info", message = e.FullMessage, code = e.Code };
        Write(obj);
    }

    public void OnWarning(LogEventArgs e)
    {
        var obj = new { ts = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), kind = "warn", message = e.FullMessage, code = e.Code };
        Write(obj);
    }

    public void OnError(LogEventArgs e)
    {
        var obj = new { ts = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), kind = "error", message = e.FullMessage, code = e.Code };
        Write(obj);
    }

    public void OnVerbose(LogEventArgs e)
    {
        var obj = new { ts = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), kind = "verbose", message = e.FullMessage };
        Write(obj);
    }

    public void OnDebug(LogEventArgs e)
    {
        var obj = new { ts = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), kind = "debug", message = e.FullMessage };
        Write(obj);
    }

    private void Write(object o)
    {
        if (_disposed) return;
        try {
            var line = System.Text.Json.JsonSerializer.Serialize(o, DomainDetective.Helpers.JsonOptions.Default);
            _writer.WriteLine(line);
            _writer.Flush();
        } catch { /* best effort */ }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _writer.Flush(); _writer.Dispose(); } catch { }
    }
}
