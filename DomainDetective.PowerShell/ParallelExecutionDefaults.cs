using System;

namespace DomainDetective.PowerShell;

internal static class ParallelExecutionDefaults {
    // Default parallelism bounds for cmdlet-level throttling.
    internal const int MinParallelism = 1;
    internal const int MaxParallelism = 128;
    internal const int DefaultMinThrottle = 2;
    internal const int DefaultMaxThrottle = 32;

    internal static int GetThrottleLimit(int? requested) {
        if (requested.HasValue && requested.Value > 0) {
            return requested.Value;
        }
        return Clamp(Environment.ProcessorCount * 2, DefaultMinThrottle, DefaultMaxThrottle);
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
