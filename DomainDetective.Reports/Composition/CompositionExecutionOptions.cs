using System;

namespace DomainDetective.Reports;

public sealed class CompositionExecutionOptions
{
    public bool EnableParallelism { get; set; } = true;
    public int? MaxParallelism { get; set; }

    internal int GetEffectiveMaxParallelism()
    {
        if (!EnableParallelism)
        {
            return 1;
        }
        if (MaxParallelism.HasValue && MaxParallelism.Value > 0)
        {
            return MaxParallelism.Value;
        }

        var computed = Environment.ProcessorCount * 2;
        if (computed < 1)
        {
            return 1;
        }
        if (computed > 32)
        {
            return 32;
        }
        return computed;
    }
}
