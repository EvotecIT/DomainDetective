using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Detects potential DNS tunneling activity from query logs.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class DnsTunnelingAnalysis
{
    /// <summary>Collection of detected issues.</summary>
    public List<DnsTunnelingAlert> Alerts { get; private set; } = new();
    /// <summary>Maximum queries allowed per <see cref="FrequencyInterval"/>.</summary>
    public int FrequencyThreshold { get; set; } = 50;
    /// <summary>Time window for frequency detection.</summary>
    public TimeSpan FrequencyInterval { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Parses <paramref name="logLines"/> looking for tunneling patterns.
    /// </summary>
    /// <param name="domainName">Domain to inspect.</param>
    /// <param name="logLines">Lines from DNS query logs.</param>
    public void Analyze(string domainName, IEnumerable<string?>? logLines)
    {
        Alerts = new List<DnsTunnelingAlert>();
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

            var label = query.Substring(0, query.Length - domainName.Length).TrimEnd('.');
            var first = label.Split('.').FirstOrDefault() ?? string.Empty;
            if (first.Length > 50 || LooksEncoded(first))
            {
                Alerts.Add(new DnsTunnelingAlert { Domain = query, Reason = "Suspicious subdomain" });
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
                    queue.Clear();
                }
            }
        }
    }

    private static bool LooksEncoded(string label)
    {
        if (label.Length < 20)
        {
            return false;
        }
        bool base64 = label.All(c => char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=');
        bool hex = label.All(c => Uri.IsHexDigit(c));
        return base64 || hex;
    }
}
