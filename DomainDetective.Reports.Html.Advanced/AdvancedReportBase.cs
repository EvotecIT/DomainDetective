using System.Collections.Generic;
using HtmlForgeX;

namespace DomainDetective.Reports.Html.Advanced;

/// <summary>
/// Provides base functionality for advanced HTML reports.
/// Handles standard layout and progress log rendering.
/// </summary>
public abstract class AdvancedReportBase {
    private readonly List<LogEventArgs> _progressLog = new();

    /// <summary>
    /// Collected progress log entries.
    /// </summary>
    protected IReadOnlyList<LogEventArgs> ProgressLog => _progressLog;

    /// <summary>
    /// Associated health check instance.
    /// </summary>
    protected DomainHealthCheck HealthCheck { get; }

    /// <summary>
    /// Domain name used for the report.
    /// </summary>
    protected string Domain { get; }

    protected AdvancedReportBase(DomainHealthCheck healthCheck, string domain, IEnumerable<LogEventArgs>? progressLog = null) {
        HealthCheck = healthCheck;
        Domain = domain;
        if (progressLog != null) {
            _progressLog.AddRange(progressLog);
        }
    }

    /// <summary>
    /// Adds a progress log entry to the report.
    /// </summary>
    protected void AddProgressLog(LogEventArgs entry) {
        _progressLog.Add(entry);
    }

    /// <summary>
    /// Creates a new HTML document with common settings.
    /// </summary>
    protected static Document CreateDocument(string title) {
        return new Document {
            Head = {
                Title = title,
                Author = "DomainDetective",
            },
            LibraryMode = LibraryMode.Online,
            ThemeMode = ThemeMode.Light
        };
    }

    /// <summary>
    /// Renders collected progress log entries as a list.
    /// </summary>
    protected void RenderProgressLog(TablerPage page) {
        if (_progressLog.Count == 0) {
            return;
        }

        page.Divider("Scan Progress");
        page.Row(row => {
            row.Column(TablerColumnNumber.Twelve, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Progress Log"));
                    card.Body(body => {
                        body.AddList(list => {
                            list.WithItems(items => {
                                foreach (var entry in _progressLog) {
                                    var text = entry.FullMessage;
                                    if (entry.ProgressPercentage.HasValue) {
                                        text += $" ({entry.ProgressPercentage.Value}%)";
                                    }
                                    items.Item(text);
                                }
                            });
                        });
                    });
                });
            });
        });
    }
}
