using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
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
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the url value.</summary>
    public Uri? Url { get; private set; }
    /// <summary>Gets or sets the success value.</summary>
    public bool Success { get; private set; }
    /// <summary>Gets or sets the status code value.</summary>
    public int StatusCode { get; private set; }
    /// <summary>Gets or sets the ttfb milliseconds value.</summary>
    public long TtfbMilliseconds { get; private set; }
    /// <summary>Gets or sets the total milliseconds value.</summary>
    public long TotalMilliseconds { get; private set; }
    /// <summary>Gets the important headers value.</summary>
    public Dictionary<string, string> ImportantHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Represents the is https value.</summary>
    public bool IsHttps => Url?.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>Gets the assessments value.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>
    /// Performs a HEAD probe, falls back to a header-only GET for 405/501 responses, and records timing and posture.
    /// </summary>
    public async Task ProbeAsync(string url, InternalLogger? logger = null, CancellationToken ct = default)
    {
        Subject = url;
        Url = null;
        Success = false;
        StatusCode = 0;
        TtfbMilliseconds = 0;
        TotalMilliseconds = 0;
        ImportantHeaders.Clear();
        Assessments.Clear();
        Url = new Uri(url, UriKind.Absolute);
        var client = SharedHttpClient.Instance;
        var sw = Stopwatch.StartNew();
        HttpResponseMessage? response = null;
        try
        {
            using var headRequest = new HttpRequestMessage(HttpMethod.Head, Url);
            response = await client.SendAsync(headRequest, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.MethodNotAllowed || response.StatusCode == HttpStatusCode.NotImplemented)
            {
                response.Dispose();
                response = null;
                using var getRequest = new HttpRequestMessage(HttpMethod.Get, Url);
                response = await client.SendAsync(getRequest, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            }

            TtfbMilliseconds = sw.ElapsedMilliseconds;
            StatusCode = (int)response.StatusCode;
            // Basic header posture
            Capture("strict-transport-security", response);
            Capture("content-security-policy", response);
            Capture("x-content-type-options", response);
            Capture("referrer-policy", response);
            Capture("permissions-policy", response);

            if (StatusCode >= 200 && StatusCode < 400)
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
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
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
            response?.Dispose();
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
