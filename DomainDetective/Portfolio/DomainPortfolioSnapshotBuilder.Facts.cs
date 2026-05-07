using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;

namespace DomainDetective;

public static partial class DomainPortfolioSnapshotBuilder {
    private const char CollectionEscape = '\\';
    private const char CollectionSeparator = '|';

    private static readonly ConcurrentDictionary<Type, PropertyInfo[]> PropertyCache = new();
    private static readonly ConcurrentDictionary<string, string> LabelCache = new(StringComparer.Ordinal);

    // Infrastructure and recommendation surfaces are intentionally excluded from flat fact storage.
    private static readonly HashSet<string> IgnoredPropertyNames = new(StringComparer.OrdinalIgnoreCase) {
        "Assessments",
        "Recommendations",
        "DnsConfiguration",
        "QueryDnsOverride",
        "Logger"
    };

    /// <summary>
    /// Extracts storage-friendly scalar facts from public analysis properties.
    /// </summary>
    /// <remarks>
    /// <see cref="DateTime"/> values with <see cref="DateTimeKind.Unspecified"/> are treated as UTC because analysis objects are expected to store captured timestamps in UTC.
    /// </remarks>
    internal static IEnumerable<DomainPortfolioFact> ExtractFacts(object analysis) {
        var properties = PropertyCache.GetOrAdd(
            analysis.GetType(),
            static type => type.GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .Where(static property => property.GetMethod != null && property.GetIndexParameters().Length == 0)
                .OrderBy(static property => property.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray());

        return properties
            .Where(static property => !IgnoredPropertyNames.Contains(property.Name))
            .Select(property => TryExtractFact(property, analysis))
            .Where(static fact => fact != null)
            .Select(static fact => fact!);
    }

    private static DomainPortfolioFact? TryExtractFact(PropertyInfo property, object analysis) {
        if (!TryRead(property, analysis, out var value)) {
            return null;
        }

        if (!TryFormat(value, out var formatted, out var kind)) {
            return null;
        }

        return new DomainPortfolioFact {
            Key = property.Name,
            Label = ToDisplayLabel(property.Name),
            Value = formatted,
            Kind = kind
        };
    }

    private static bool TryRead(PropertyInfo property, object instance, out object value) {
        try {
            value = property.GetValue(instance)!;
            return value != null;
        } catch (TargetInvocationException ex) when (ex.InnerException is NotSupportedException) {
            value = null!;
            return false;
        }
    }

    private static bool TryFormat(object value, out string formatted, out DomainPortfolioFactKind kind) {
        formatted = string.Empty;
        kind = DomainPortfolioFactKind.String;

        if (value is IDictionary) {
            return false;
        }

        if (value is IEnumerable enumerable && value is not string) {
            var items = new List<string>();
            foreach (var item in enumerable) {
                if (item == null) continue;
                if (!TryFormatScalar(item, out var itemValue, out _)) continue;
                if (!string.IsNullOrWhiteSpace(itemValue)) items.Add(itemValue);
            }

            if (items.Count == 0) {
                formatted = string.Empty;
                return false;
            }

            // Portfolio collection facts are canonical sets; string variants differing only by case are equivalent.
            formatted = string.Join("|", items
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
                .Select(EscapeCollectionItem));
            kind = DomainPortfolioFactKind.Collection;
            return true;
        }

        return TryFormatScalar(value, out formatted, out kind);
    }

    private static bool TryFormatScalar(object value, out string formatted, out DomainPortfolioFactKind kind) {
        formatted = string.Empty;
        kind = DomainPortfolioFactKind.String;

        var type = Nullable.GetUnderlyingType(value.GetType()) ?? value.GetType();
        if (type == typeof(string)) {
            formatted = ((string)value).Trim();
            kind = DomainPortfolioFactKind.String;
            return formatted.Length > 0;
        }

        if (type == typeof(bool)) {
            formatted = ((bool)value) ? "true" : "false";
            kind = DomainPortfolioFactKind.Boolean;
            return true;
        }

        if (type.IsEnum) {
            formatted = value.ToString() ?? string.Empty;
            kind = DomainPortfolioFactKind.String;
            return formatted.Length > 0;
        }

        if (IsNumeric(type)) {
            formatted = Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
            kind = DomainPortfolioFactKind.Number;
            return formatted.Length > 0;
        }

        if (type == typeof(DateTime)) {
            var dateTime = NormalizeDateTime((DateTime)value);
            if (dateTime == DateTime.MinValue) {
                return false;
            }

            formatted = dateTime.ToString("O", CultureInfo.InvariantCulture);
            kind = DomainPortfolioFactKind.DateTime;
            return true;
        }

        if (type == typeof(DateTimeOffset)) {
            var dateTimeOffset = ((DateTimeOffset)value).ToUniversalTime();
            if (dateTimeOffset == DateTimeOffset.MinValue) {
                return false;
            }

            formatted = dateTimeOffset.ToString("O", CultureInfo.InvariantCulture);
            kind = DomainPortfolioFactKind.DateTime;
            return true;
        }

        if (type == typeof(TimeSpan)) {
            var duration = (TimeSpan)value;
            if (duration == TimeSpan.Zero) {
                // Analysis duration fields use zero as the default not-collected value.
                return false;
            }

            formatted = duration.ToString("c", CultureInfo.InvariantCulture);
            kind = DomainPortfolioFactKind.Duration;
            return true;
        }

        if (value is Uri uri) {
            formatted = uri.ToString();
            kind = DomainPortfolioFactKind.String;
            return formatted.Length > 0;
        }

        return false;
    }

    private static string EscapeCollectionItem(string value) {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value) {
            if (character == CollectionEscape || character == CollectionSeparator) {
                builder.Append(CollectionEscape);
            }

            builder.Append(character);
        }

        return builder.ToString();
    }

    private static List<string> SplitCollectionValue(string value) {
        var items = new List<string>();
        var builder = new StringBuilder(value.Length);
        var escaped = false;

        foreach (var character in value) {
            if (escaped) {
                builder.Append(character);
                escaped = false;
                continue;
            }

            if (character == CollectionEscape) {
                escaped = true;
                continue;
            }

            if (character == CollectionSeparator) {
                AddCollectionValue(items, builder);
                continue;
            }

            builder.Append(character);
        }

        if (escaped) {
            builder.Append(CollectionEscape);
        }

        AddCollectionValue(items, builder);
        return items;
    }

    private static void AddCollectionValue(List<string> items, StringBuilder builder) {
        var item = builder.ToString().Trim();
        if (item.Length > 0) {
            items.Add(item);
        }

        builder.Clear();
    }

    private static DateTime NormalizeDateTime(DateTime value) {
        if (value == DateTime.MinValue) {
            return DateTime.MinValue;
        }

        if (value.Kind == DateTimeKind.Unspecified) {
            // Analysis objects that do not set Kind are expected to carry UTC values already.
            return DateTime.SpecifyKind(value, DateTimeKind.Utc);
        }

        return value.ToUniversalTime();
    }

    private static bool IsNumeric(Type type)
        => type == typeof(byte) ||
           type == typeof(sbyte) ||
           type == typeof(short) ||
           type == typeof(ushort) ||
           type == typeof(int) ||
           type == typeof(uint) ||
           type == typeof(long) ||
           type == typeof(ulong) ||
           type == typeof(float) ||
           type == typeof(double) ||
           type == typeof(decimal);

    internal static string ToDisplayLabel(string key) {
        if (string.IsNullOrWhiteSpace(key)) return string.Empty;
        return LabelCache.GetOrAdd(key, static value => BuildDisplayLabel(value));
    }

    private static string BuildDisplayLabel(string value) {
        var builder = new StringBuilder(value.Length + 8);
        for (var i = 0; i < value.Length; i++) {
            var current = value[i];
            if (current == '_' || current == '-') {
                AppendSpace(builder);
                continue;
            }

            if (builder.Length > 0 && char.IsUpper(current)) {
                var previous = value[i - 1];
                var next = i + 1 < value.Length ? value[i + 1] : '\0';
                if (char.IsLower(previous) ||
                    char.IsDigit(previous) && !char.IsDigit(next) ||
                    char.IsUpper(previous) && char.IsLower(next) && HasAcronymPrefix(value, i)) {
                    AppendSpace(builder);
                }
            }

            builder.Append(current);
        }

        return builder.ToString().Trim();
    }

    private static bool HasAcronymPrefix(string value, int index) {
        var uppercaseCount = 0;
        for (var i = index - 1; i >= 0 && char.IsUpper(value[i]); i--) {
            uppercaseCount++;
        }

        return uppercaseCount >= 2;
    }

    private static void AppendSpace(StringBuilder builder) {
        if (builder.Length == 0) return;
        if (builder[builder.Length - 1] == ' ') return;
        builder.Append(' ');
    }
}
