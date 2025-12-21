using System;
using System.Collections;
using System.Collections.Generic;

namespace DomainDetective.Reports;

internal static class CompositionUtilities
{
    public static IReadOnlyList<object> Flatten(IReadOnlyList<object> items)
    {
        if (items == null || items.Count == 0)
        {
            return Array.Empty<object>();
        }

        var flat = new List<object>();
        foreach (var raw in items)
        {
            foreach (var it in EnumeratePossiblyNested(raw))
            {
                if (it != null)
                {
                    flat.Add(it);
                }
            }
        }
        return flat;
    }

    public static IReadOnlyList<string> ExtractSubjects(IReadOnlyList<object> items)
    {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in items ?? Array.Empty<object>())
        {
            foreach (var it in EnumeratePossiblyNested(raw))
            {
                var subject = TryGetSubject(it);
                if (!string.IsNullOrWhiteSpace(subject) && seen.Add(subject!))
                {
                    list.Add(subject!);
                }
            }
        }
        return list;
    }

    public static string BuildSubjectLabel(IReadOnlyList<string> subjects)
    {
        if (subjects == null || subjects.Count == 0)
        {
            return "report";
        }
        if (subjects.Count == 1)
        {
            return subjects[0];
        }
        if (subjects.Count == 2)
        {
            return $"{subjects[0]}+{subjects[1]}";
        }
        return $"{subjects[0]}+{subjects[1]}(+{subjects.Count - 2})";
    }

    private static IEnumerable<object> EnumeratePossiblyNested(object? item)
    {
        if (item == null)
        {
            yield break;
        }

        if (item is IEnumerable enumerable && item is not string)
        {
            foreach (var entry in enumerable)
            {
                if (entry != null)
                {
                    yield return entry;
                }
            }
        }
        else
        {
            yield return item;
        }
    }

    private static string? TryGetSubject(object? item)
    {
        if (item == null)
        {
            return null;
        }

        try
        {
            var prop = item.GetType().GetProperty("Subject");
            var value = prop?.GetValue(item);
            return value?.ToString();
        }
        catch
        {
            return null;
        }
    }
}
