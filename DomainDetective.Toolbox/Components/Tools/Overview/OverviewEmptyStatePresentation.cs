using System;
using System.Collections.Generic;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

internal static class OverviewEmptyStatePresentation
{
    public static DomainOverviewDetailCardView BuildCard(string title, string valueLabel, string summary, IReadOnlyList<string>? tags = null, IReadOnlyList<string>? samples = null)
    {
        return new DomainOverviewDetailCardView
        {
            Title = title ?? string.Empty,
            ValueLabel = valueLabel ?? string.Empty,
            Summary = summary ?? string.Empty,
            Tags = tags ?? Array.Empty<string>(),
            Samples = samples ?? Array.Empty<string>()
        };
    }
}
