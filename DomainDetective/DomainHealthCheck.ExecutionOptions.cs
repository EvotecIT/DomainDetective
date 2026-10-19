using System;

namespace DomainDetective;

/// <summary>
/// Execution settings for domain health checks.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class HealthCheckExecutionOptions {
    /// <summary>
    /// Enables parallel execution of independent checks.
    /// </summary>
    public bool EnableParallelism { get; set; } = true;

    /// <summary>
    /// Optional override for maximum concurrent checks.
    /// </summary>
    public int? MaxParallelism { get; set; }

    /// <summary>
    /// Optional override for maximum concurrent domain runs in batch execution.
    /// </summary>
    public int? MaxDomainParallelism { get; set; }

    /// <summary>
    /// Optional override for DNS resolver concurrency hints and the shared recursive-query admission cap across a batch.
    /// The default scales with processor count up to 64 in-flight queries.
    /// </summary>
    public int? DnsParallelism { get; set; }

    /// <summary>
    /// Clears logger message de-duplication on each run.
    /// </summary>
    public bool ResetLogDedupOnRun { get; set; } = true;

    /// <summary>
    /// Enables caching of shared MX lookups within a single run.
    /// </summary>
    public bool EnableSharedMxCache { get; set; } = true;

    /// <summary>
    /// When enabled, DKIM verification records results for selectors even when no DKIM TXT record exists.
    /// </summary>
    /// <remarks>
    /// This is useful when you have an organization-defined list of required selectors and want to detect drift.
    /// </remarks>
    public bool IncludeMissingDkimSelectors { get; set; }

    /// <summary>
    /// When enabled, BIMI verification skips downloading the indicator SVG.
    /// </summary>
    /// <remarks>
    /// This is useful for drift detection scenarios where you want to validate DNS posture without relying on external HTTP availability.
    /// </remarks>
    public bool SkipBimiIndicatorDownload { get; set; }

    /// <summary>HTTPS port used by HTTP, CERT and WEBSITE in a combined verification run.</summary>
    public int WebsitePort { get; set; } = 443;

    /// <summary>Collects separate plain HTTP evidence alongside the selected checks without replacing HTTPS results.</summary>
    public bool IncludePlainHttp { get; set; }

    /// <summary>Checks takeover-prone CNAME targets as an owned phase of the combined verification run.</summary>
    public bool IncludeTakeoverCname { get; set; }

    internal int GetEffectiveMaxParallelism() {
        if (MaxParallelism.HasValue && MaxParallelism.Value > 0) {
            return MaxParallelism.Value;
        }
        return Clamp(Environment.ProcessorCount * 4, 4, 32);
    }

    internal int GetEffectiveDomainParallelism() {
        if (MaxDomainParallelism.HasValue && MaxDomainParallelism.Value > 0) {
            return MaxDomainParallelism.Value;
        }
        return Clamp(Environment.ProcessorCount * 2, 2, 16);
    }

    internal int GetEffectiveDnsParallelism() {
        if (DnsParallelism.HasValue && DnsParallelism.Value > 0) {
            return DnsParallelism.Value;
        }
        return Clamp(Environment.ProcessorCount * 2, 4, 64);
    }

    private static int Clamp(int value, int min, int max) {
        if (value < min) {
            return min;
        }
        if (value > max) {
            return max;
        }
        return value;
    }
}
