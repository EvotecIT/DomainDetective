using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Performs a single HTTP(S) probe capturing TTFB/total latency, status and basic header posture.
/// </summary>
/// <para>Scaffold for future synthetic monitoring and scheduling.</para>
public sealed class UptimeProbeAnalysis : IHasAssessments
{
    public string? Subject { get; set; }
    public Uri? Url { get; private set; }
    public bool Success { get; private set; }
    public int StatusCode { get; private set; }
    public long TtfbMilliseconds { get; private set; }
    public long TotalMilliseconds { get; private set; }
    public Dictionary<string, string> ImportantHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool IsHttps => Url?.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) == true;

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>
    /// Performs a HEAD probe (optionally falls back to GET) and records timing and posture.
    /// </summary>
    public async Task ProbeAsync(string url, InternalLogger? logger = null, CancellationToken ct = default)
    {
        Subject = url;
        Url = new Uri(url, UriKind.Absolute);
        using var client = SharedHttpClient.Instance;
        using var req = new HttpRequestMessage(HttpMethod.Head, Url);
        var sw = Stopwatch.StartNew();
        try
        {
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            TtfbMilliseconds = sw.ElapsedMilliseconds;
            StatusCode = (int)resp.StatusCode;
            // Basic header posture
            Capture("strict-transport-security", resp);
            Capture("content-security-policy", resp);
            Capture("x-content-type-options", resp);
            Capture("referrer-policy", resp);
            Capture("permissions-policy", resp);

            if ((int)resp.StatusCode >= 200 && (int)resp.StatusCode < 400)
            {
                Success = true;
                logger?.WriteInformationCode(UptimeCodes.UptimeOk, $"Uptime OK {StatusCode} ({TtfbMilliseconds} ms TTFB)");
            }
            else
            {
                Success = false;
                logger?.WriteWarningCode(UptimeCodes.UptimeBadStatus, $"Uptime status {StatusCode} ({TtfbMilliseconds} ms TTFB)");
            }
        }
        catch (Exception ex)
        {
            TtfbMilliseconds = sw.ElapsedMilliseconds;
            Success = false;
            Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Category = "UPTIME", Target = url, Code = UptimeCodes.UptimeException, Message = ex.Message });
            logger?.WriteErrorCode(UptimeCodes.UptimeException, $"Uptime exception: {ex.Message}");
        }
        finally
        {
            sw.Stop();
            TotalMilliseconds = sw.ElapsedMilliseconds;
        }
    }

    private void Capture(string name, HttpResponseMessage resp)
    {
        if (resp.Headers.TryGetValues(name, out var values))
        {
            ImportantHeaders[name] = string.Join(", ", values);
            Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Category = "HTTP", Target = Url?.Host, Code = $"HTTP.Header.{name}", Message = $"Header present: {name}" });
        }
    }

    /// <summary>Serializes a simple JSON snapshot to the given path.</summary>
    public async Task SaveSnapshotAsync(string path, CancellationToken ct = default)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            Subject,
            Url = Url?.ToString(),
            Success,
            StatusCode,
            TtfbMilliseconds,
            TotalMilliseconds,
            ImportantHeaders,
            TimestampUtc = DateTimeOffset.UtcNow
        }, DomainHealthCheck.JsonOptions);
        #if NET472
        System.IO.File.WriteAllText(path, json);
        await Task.CompletedTask;
        #else
        await System.IO.File.WriteAllTextAsync(path, json, ct).ConfigureAwait(false);
        #endif
    }
}

internal static class UptimeCodes
{
    public const string UptimeOk = "HTTP.Uptime.OK";
    public const string UptimeBadStatus = "HTTP.Uptime.BadStatus";
    public const string UptimeException = "HTTP.Uptime.Exception";
}
