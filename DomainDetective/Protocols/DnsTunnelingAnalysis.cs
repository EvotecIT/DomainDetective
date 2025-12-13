using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Detects potential DNS tunneling activity from query logs.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class DnsTunnelingAnalysis : IHasAssessments
{
    private const int MaxLabelLength = 50;
    private const int MinEncodingLength = 20;
    /// <summary>Domain under analysis.</summary>
    public string? Subject { get; set; }
    /// <summary>Collection of detected issues.</summary>
    public List<DnsTunnelingAlert> Alerts { get; private set; } = new();
    /// <summary>Maximum queries allowed per <see cref="FrequencyInterval"/>.</summary>
    public int FrequencyThreshold { get; set; } = 50;
    /// <summary>Time window for frequency detection.</summary>
    public TimeSpan FrequencyInterval { get; set; } = TimeSpan.FromSeconds(1);

    public List<Assessment> Assessments { get; } = new();

    /// <summary>
    /// Parses DNS query log lines looking for tunneling patterns.
    /// </summary>
    /// <param name="domainName">Domain to inspect.</param>
    /// <param name="logLines">Lines from DNS query logs.</param>
    public void Analyze(string domainName, IEnumerable<string?>? logLines)
    {
        Subject = domainName;
        Alerts = new List<DnsTunnelingAlert>();
        Assessments.Clear();
        var queue = new Queue<DateTimeOffset>();
        if (logLines == null)
        {
            return;
        }
        foreach (var line in logLines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            DateTimeOffset ts;
            string query;
            if (parts.Length > 1 && DateTimeOffset.TryParse(parts[0], out ts))
            {
                query = parts[1];
            }
            else
            {
                ts = DateTimeOffset.MinValue;
                query = parts[0];
            }

            if (!query.EndsWith(domainName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (query.Length <= domainName.Length)
            {
                continue; // Skip invalid queries
            }

            var label = query.Substring(0, query.Length - domainName.Length).TrimEnd('.');
            var first = label.Split('.').FirstOrDefault() ?? string.Empty;
            if (first.Length > MaxLabelLength || LooksEncoded(first))
            {
                Alerts.Add(new DnsTunnelingAlert { Domain = query, Reason = "Suspicious subdomain" });
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DnsTunneling",
                    Target = query,
                    Code = DnsTunnelingCodes.SuspiciousLabel,
                    Message = "Suspicious long or encoded subdomain label detected"
                });
            }

            if (ts != DateTimeOffset.MinValue)
            {
                queue.Enqueue(ts);
                while (queue.Count > 0 && ts - queue.Peek() > FrequencyInterval)
                {
                    queue.Dequeue();
                }
                if (queue.Count > FrequencyThreshold)
                {
                    Alerts.Add(new DnsTunnelingAlert { Domain = query, Reason = "High query rate" });
                    Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DnsTunneling",
                        Target = domainName,
                        Code = DnsTunnelingCodes.HighFrequency,
                        Message = "High DNS query rate observed within interval"
                    });
                    queue.Clear();
                }
            }
        }

        if (Alerts.Count == 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "DnsTunneling",
                Target = domainName,
                Code = DnsTunnelingCodes.NoIndicators,
                Message = "No tunneling indicators found in DNS logs",
            });
        }
    }

    private static bool LooksEncoded(string label)
    {
        if (label.Length < MinEncodingLength)
        {
            return false;
        }
        bool base64 = label.All(c => char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=');
        bool hex = label.All(c => Uri.IsHexDigit(c));
        return base64 || hex;
    }
}
