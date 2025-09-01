using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Bridges InternalLogger events into structured <see cref="Assessment"/> entries.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class AssessmentCollector : IDisposable {
    private readonly InternalLogger _logger;
    private readonly List<Assessment> _sink;

    private readonly Stack<ScopeFrame> _scope = new();

    private readonly EventHandler<LogEventArgs> _onWarn;
    private readonly EventHandler<LogEventArgs> _onError;
    private readonly EventHandler<LogEventArgs> _onInfo;

    private readonly object _lock = new();

    private AssessmentCollector(InternalLogger logger, List<Assessment> sink, string? defaultCategory = null, string? defaultTarget = null, string? defaultSource = null) {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));

        if (!string.IsNullOrWhiteSpace(defaultCategory) || !string.IsNullOrWhiteSpace(defaultTarget) || !string.IsNullOrWhiteSpace(defaultSource)) {
            _scope.Push(new ScopeFrame(defaultCategory, defaultTarget, defaultSource));
        }

        _onWarn = (_, e) => Add(AssessmentSeverity.Warning, e.FullMessage, e.Code);
        _onError = (_, e) => Add(AssessmentSeverity.Error, e.FullMessage, e.Code);
        _onInfo  = (_, e) => Add(AssessmentSeverity.Info, e.FullMessage, e.Code);

        _logger.OnWarningMessage += _onWarn;
        _logger.OnErrorMessage += _onError;
        // Information is less frequently used but can carry useful advice
        _logger.OnInformationMessage += _onInfo;
    }

    /// <summary>
    /// Creates a collector that stores assessments inside the provided analysis object.
    /// </summary>
    public static AssessmentCollector ForAnalysis(InternalLogger logger, IHasAssessments analysis, string? category = null, string? target = null, string? source = null)
        => new(logger, analysis.Assessments, category, target, source);

    /// <summary>
    /// Pushes a new scope changing category/target/source for subsequent events.
    /// </summary>
    public IDisposable PushScope(string? category = null, string? target = null, string? source = null) {
        _scope.Push(new ScopeFrame(category, target, source));
        return new Popper(this);
    }

    /// <summary>
    /// Convenience helper to set just the target for a subset of operations.
    /// </summary>
    public IDisposable PushTarget(string target) => PushScope(target: target);

    /// <summary>
    /// Adds an information assessment directly (not driven by the logger).
    /// </summary>
    public void AddInfo(string message, string? code = null, string? category = null, string? target = null, string? source = null) {
        Add(AssessmentSeverity.Info, message, code, category, target, source);
    }

    private readonly HashSet<string> _seen = new();

    private void Add(AssessmentSeverity severity, string message, string? code = null, string? category = null, string? target = null, string? source = null) {
        lock (_lock) {
            string? cat = category;
            string? tgt = target;
            string? src = source;
            if (_scope.Count > 0) {
                var top = _scope.Peek();
                cat ??= top.Category;
                tgt ??= top.Target;
                src ??= top.Source;
            }
            var key = string.Join("|", new[] { cat ?? "General", tgt ?? string.Empty, code ?? string.Empty, message ?? string.Empty });
            if (_seen.Contains(key)) return;
            _seen.Add(key);
            _sink.Add(new Assessment {
                Severity = severity,
                Message = message ?? string.Empty,
                Code = code,
                Category = string.IsNullOrWhiteSpace(cat) ? "General" : cat!,
                Target = tgt,
                Source = src,
                Timestamp = DateTimeOffset.UtcNow,
            });
        }
    }

    private void Pop() {
        if (_scope.Count > 0) {
            _scope.Pop();
        }
    }

    public void Dispose() {
        _logger.OnWarningMessage -= _onWarn;
        _logger.OnErrorMessage -= _onError;
        _logger.OnInformationMessage -= _onInfo;
        _scope.Clear();
    }

    private readonly struct ScopeFrame {
        public readonly string? Category;
        public readonly string? Target;
        public readonly string? Source;
        public ScopeFrame(string? category, string? target, string? source) {
            Category = category; Target = target; Source = source;
        }
    }

    private sealed class Popper : IDisposable {
        private AssessmentCollector _owner;
        public Popper(AssessmentCollector owner) { _owner = owner; }
        public void Dispose() { _owner.Pop(); }
    }
}
