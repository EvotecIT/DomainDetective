using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    internal static IReadOnlyList<string> BuildReferences(IReadOnlyList<StandardReference> refs, IEnumerable<RecommendationAdvice> advices)
    {
        var list = new List<string>();
        if (refs != null)
        {
            foreach (var r in refs)
            {
                if (!string.IsNullOrWhiteSpace(r?.Url)) list.Add(r.Url);
                else if (!string.IsNullOrWhiteSpace(r?.Reference)) list.Add(r.Reference);
            }
        }
        if (advices != null)
        {
            foreach (var a in advices)
            {
                if (a?.Links != null)
                    foreach (var l in a.Links)
                        if (!string.IsNullOrWhiteSpace(l)) list.Add(l);
            }
        }
        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}

