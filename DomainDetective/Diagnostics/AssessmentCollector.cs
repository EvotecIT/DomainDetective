using System;
using System.Collections.Generic;
using System.Threading;

namespace DomainDetective;

/// <summary>
/// Bridges InternalLogger events into structured <see cref="Assessment"/> entries.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class AssessmentCollector : IDisposable {
    private static readonly AsyncLocal<AssessmentCollector?> ActiveCollector = new();

    private readonly InternalLogger _logger;
    private readonly List<Assessment> _sink;
    private readonly AssessmentCollector? _parentCollector;

    private readonly Stack<ScopeFrame> _scope = new();

    private readonly EventHandler<LogEventArgs> _onWarn;
    private readonly EventHandler<LogEventArgs> _onError;
    private readonly EventHandler<LogEventArgs> _onInfo;
    private readonly Action<AssessmentSeverity, LogEventArgs> _onSuppressedCoded;

    private readonly object _lock = new();

    private AssessmentCollector(InternalLogger logger, List<Assessment> sink, string? defaultCategory = null, string? defaultTarget = null, string? defaultSource = null) {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));

        if (!string.IsNullOrWhiteSpace(defaultCategory) || !string.IsNullOrWhiteSpace(defaultTarget) || !string.IsNullOrWhiteSpace(defaultSource)) {
            _scope.Push(new ScopeFrame(defaultCategory, defaultTarget, defaultSource));
        }

        _onWarn = (_, e) => Capture(AssessmentSeverity.Warning, e);
        _onError = (_, e) => Capture(AssessmentSeverity.Error, e);
        _onInfo = (_, e) => Capture(AssessmentSeverity.Info, e);
        _onSuppressedCoded = Capture;

        _logger.OnWarningMessage += _onWarn;
        _logger.OnErrorMessage += _onError;
        // Information is less frequently used but can carry useful advice
        _logger.OnInformationMessage += _onInfo;
        _logger.OnSuppressedCodedMessage += _onSuppressedCoded;

        _parentCollector = ActiveCollector.Value;
        ActiveCollector.Value = this;
    }

    /// <summary>
    /// Creates a collector that stores assessments inside the provided analysis object.
    /// </summary>
    public static AssessmentCollector ForAnalysis(InternalLogger logger, IHasAssessments analysis, string? category = null, string? target = null, string? source = null)
        => new(logger, analysis.Assessments, category, target, source);

    /// <summary>
    /// Pushes a new scope, inheriting category, target, and source values that are not supplied.
    /// </summary>
    public IDisposable PushScope(string? category = null, string? target = null, string? source = null) {
        ScopeFrame parent = _scope.Count > 0 ? _scope.Peek() : default;
        _scope.Push(new ScopeFrame(category ?? parent.Category, target ?? parent.Target, source ?? parent.Source));
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

    private void Capture(AssessmentSeverity severity, LogEventArgs eventArgs) {
        if (IsActiveForCurrentFlow()) {
            Add(severity, eventArgs.FullMessage, eventArgs.Code);
        }
    }

    private bool IsActiveForCurrentFlow() {
        for (var collector = ActiveCollector.Value; collector != null; collector = collector._parentCollector) {
            if (ReferenceEquals(collector, this)) {
                return true;
            }
        }
        return false;
    }

    /// <summary>Executes the dispose operation.</summary>
    public void Dispose() {
        _logger.OnWarningMessage -= _onWarn;
        _logger.OnErrorMessage -= _onError;
        _logger.OnInformationMessage -= _onInfo;
        _logger.OnSuppressedCodedMessage -= _onSuppressedCoded;
        _scope.Clear();
        if (ReferenceEquals(ActiveCollector.Value, this)) {
            ActiveCollector.Value = _parentCollector;
        }
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
