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
    /// Optional override for DNS resolver concurrency hints.
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

    internal int GetEffectiveMaxParallelism() {
        if (MaxParallelism.HasValue && MaxParallelism.Value > 0) {
            return MaxParallelism.Value;
        }
        return Clamp(Environment.ProcessorCount * 4, 4, 32);
    }

    internal int GetEffectiveDnsParallelism() {
        if (DnsParallelism.HasValue && DnsParallelism.Value > 0) {
            return DnsParallelism.Value;
        }
        return Clamp(Environment.ProcessorCount * 2, 4, 32);
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
