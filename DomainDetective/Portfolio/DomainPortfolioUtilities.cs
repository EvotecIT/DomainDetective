using System;
using System.Collections.Generic;

namespace DomainDetective;

internal static class DomainPortfolioUtilities {
    public static T SinglePortfolioItem<T>(IEnumerable<T> items, string itemKind, string key) {
        using var enumerator = items.GetEnumerator();
        if (!enumerator.MoveNext()) {
            throw new InvalidOperationException($"No portfolio {itemKind} for key '{key}' was found.");
        }

        var first = enumerator.Current;
        if (enumerator.MoveNext()) {
            throw new InvalidOperationException($"Duplicate portfolio {itemKind} key '{key}' encountered.");
        }

        return first;
    }
}
