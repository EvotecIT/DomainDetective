using System;
using System.Collections.Generic;

namespace DomainDetective.Reports;

public sealed class CompositionWorkPlan<TPayload>
{
    public CompositionWorkPlan(IReadOnlyList<TPayload> items, string? description = null)
    {
        Items = items ?? throw new ArgumentNullException(nameof(items));
        Description = description ?? string.Empty;
    }

    public IReadOnlyList<TPayload> Items { get; }
    public string Description { get; }
}
