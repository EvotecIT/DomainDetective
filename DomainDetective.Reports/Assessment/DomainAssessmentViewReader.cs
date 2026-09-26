using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using DomainDetective.Narratives;

namespace DomainDetective.Reports;

/// <summary>
/// Reads DomainDetective view objects (<c>SpfRecordInfo</c>, <c>DmarcRecordInfo</c>, ...) by their shared naming
/// convention. The views have no common interface, so members are discovered once per type and cached.
/// </summary>
internal sealed class DomainAssessmentViewReader {
    private static readonly ConcurrentDictionary<Type, DomainAssessmentViewReader> Cache = new();

    // Members with a fixed meaning; everything else is treated as facts or evidence.
    private static readonly HashSet<string> Conventional = new(StringComparer.Ordinal) {
        "Check", "Area", "Subject", "Status", "Summary", "Assessments", "Recommendations", "Positives", "References",
        "Raw", "Narrative", "Highlights", "WarningCount", "ErrorCount", "InfoCount"
    };

    private readonly PropertyInfo? _check, _area, _subject, _summary, _assessments, _recommendations, _positives,
        _references, _raw, _narrative, _highlights, _errorCount, _warningCount;
    private readonly PropertyInfo[] _other;

    private DomainAssessmentViewReader(Type type) {
        Type = type;
        PropertyInfo[] properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static p => p.CanRead && p.GetIndexParameters().Length == 0)
            .ToArray();
        PropertyInfo? Find(string name) => properties.FirstOrDefault(p => p.Name == name);
        _check = Find("Check") is { } check && check.PropertyType == typeof(HealthCheckType) ? check : null;
        _area = Find("Area") is { } area && area.PropertyType == typeof(AnalysisArea) ? area : null;
        _subject = Find("Subject") is { } subject && subject.PropertyType == typeof(string) ? subject : null;
        _summary = Find("Summary") is { } summary && summary.PropertyType == typeof(string) ? summary : null;
        _assessments = Find("Assessments");
        _recommendations = Find("Recommendations");
        _positives = Find("Positives");
        _references = Find("References");
        _raw = Find("Raw");
        _narrative = Find("Narrative") is { } narrative && typeof(NarrativeSections).IsAssignableFrom(narrative.PropertyType) ? narrative : null;
        _highlights = Find("Highlights");
        _errorCount = Find("ErrorCount") is { } errors && errors.PropertyType == typeof(int) ? errors : null;
        _warningCount = Find("WarningCount") is { } warnings && warnings.PropertyType == typeof(int) ? warnings : null;
        _other = properties.Where(static p => !Conventional.Contains(p.Name)).ToArray();
    }

    public Type Type { get; }

    /// <summary>Whether the object looks like a view: it names the subject it describes.</summary>
    public bool IsView => _subject != null;

    public static DomainAssessmentViewReader For(Type type) => Cache.GetOrAdd(type, static t => new DomainAssessmentViewReader(t));

    public HealthCheckType? Check(object view) => _check != null ? (HealthCheckType?)Get(_check, view) : null;

    public AnalysisArea? Area(object view) => _area != null ? (AnalysisArea?)Get(_area, view) : null;

    public string? Subject(object view) => _subject != null ? Get(_subject, view) as string : null;

    public string? Summary(object view) => _summary != null ? Get(_summary, view) as string : null;

    public object? Raw(object view) => _raw != null ? Get(_raw, view) : null;

    public NarrativeSections? Narrative(object view) => _narrative != null ? Get(_narrative, view) as NarrativeSections : null;

    public IEnumerable<Assessment> Assessments(object view) => Sequence<Assessment>(_assessments, view);

    public IEnumerable<RecommendationAdvice> Recommendations(object view) => Sequence<RecommendationAdvice>(_recommendations, view);

    public IEnumerable<RecommendationAdvice> Positives(object view) => Sequence<RecommendationAdvice>(_positives, view);

    public IEnumerable<string> References(object view) => Sequence<string>(_references, view);

    public IEnumerable<string> Highlights(object view) => Sequence<string>(_highlights, view);

    public int ErrorCount(object view) => _errorCount != null && Get(_errorCount, view) is int count ? Math.Max(0, count) : 0;

    public int WarningCount(object view) => _warningCount != null && Get(_warningCount, view) is int count ? Math.Max(0, count) : 0;

    /// <summary>
    /// Scalar members as facts, record-like strings and long text as code, and collections as lists or tables.
    /// </summary>
    public void ReadDetails(object view, string? prefix, List<CheckFact> facts, List<CheckEvidence> evidence, int maxRows, int depth = 0) {
        foreach (PropertyInfo property in _other) {
            object? value = Get(property, view);
            if (value == null) continue;
            string label = Humanize(prefix == null ? property.Name : prefix + property.Name);
            Type type = value.GetType();
            if (IsScalar(type)) {
                string text = Format(value);
                if (text.Length == 0) continue;
                if (IsRecordText(property.Name, text)) {
                    evidence.Add(new CheckEvidence { Title = label, Kind = CheckEvidenceKind.Code, Text = text });
                } else {
                    facts.Add(new CheckFact { Label = label, Value = text });
                }
            } else if (value is IDictionary dictionary) {
                AddDictionary(label, dictionary, evidence, maxRows);
            } else if (value is IEnumerable sequence) {
                AddSequence(label, sequence, evidence, maxRows);
            } else if (depth == 0 && !typeof(NarrativeSections).IsAssignableFrom(type)) {
                // One level of nested objects (for example a policy or provider block) flattened into facts.
                For(type).ReadDetails(value, property.Name + " ", facts, evidence, maxRows, depth + 1);
            }
        }
    }

    private static void AddDictionary(string label, IDictionary dictionary, List<CheckEvidence> evidence, int maxRows) {
        var table = new CheckEvidence { Title = label, Kind = CheckEvidenceKind.Table, Columns = { "Key", "Value" } };
        foreach (DictionaryEntry entry in dictionary) {
            if (entry.Value != null && !IsScalar(entry.Value.GetType()) && entry.Value is not IEnumerable) continue;
            if (table.Rows.Count >= maxRows) {
                table.Omitted++;
                continue;
            }
            table.Rows.Add(new List<string> { Format(entry.Key), FormatCell(entry.Value) });
        }
        if (table.Rows.Count > 0) evidence.Add(table);
    }

    private static void AddSequence(string label, IEnumerable sequence, List<CheckEvidence> evidence, int maxRows) {
        var items = new List<object>();
        var total = 0;
        try {
            foreach (object? item in sequence) {
                if (item == null) continue;
                total++;
                if (items.Count < maxRows) items.Add(item);
                else if (total > 100000) break;
            }
        } catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or TargetInvocationException) {
            // A collection that cannot be enumerated is left out of the evidence.
        }
        if (items.Count == 0) return;
        if (items.All(static item => IsScalar(item.GetType()))) {
            var list = new CheckEvidence { Title = label, Kind = CheckEvidenceKind.List };
            list.Items.AddRange(items.Select(Format).Where(static text => text.Length > 0));
            list.Omitted = Math.Max(0, total - items.Count);
            if (list.Items.Count > 0) evidence.Add(list);
            return;
        }

        Type elementType = items[0].GetType();
        PropertyInfo[] columns = elementType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static p => p.CanRead && p.GetIndexParameters().Length == 0 && (IsScalar(p.PropertyType) || IsScalarSequence(p.PropertyType)))
            .Take(16)
            .ToArray();
        if (columns.Length == 0) return;
        var table = new CheckEvidence { Title = label, Kind = CheckEvidenceKind.Table };
        table.Columns.AddRange(columns.Select(static c => Humanize(c.Name)));
        foreach (object item in items) {
            table.Rows.Add(columns.Select(column => item.GetType() == elementType || column.DeclaringType!.IsInstanceOfType(item)
                ? FormatCell(Get(column, item))
                : string.Empty).ToList());
        }
        table.Omitted = Math.Max(0, total - items.Count);
        DropEmptyColumns(table);
        if (table.Columns.Count > 0) evidence.Add(table);
    }

    private static void DropEmptyColumns(CheckEvidence table) {
        for (int column = table.Columns.Count - 1; column >= 0; column--) {
            if (table.Rows.All(row => row[column].Length == 0)) {
                table.Columns.RemoveAt(column);
                foreach (List<string> row in table.Rows) row.RemoveAt(column);
            }
        }
    }

    private static IEnumerable<T> Sequence<T>(PropertyInfo? property, object view) {
        if (property == null || Get(property, view) is not IEnumerable sequence) return Array.Empty<T>();
        return sequence.OfType<T>();
    }

    private static object? Get(PropertyInfo property, object target) {
        try {
            return property.GetValue(target);
        } catch (TargetInvocationException) {
            return null;
        }
    }

    private static bool IsRecordText(string name, string text)
        => text.Length > 120 || name.EndsWith("Record", StringComparison.Ordinal) && text.IndexOf(' ') >= 0 && text.Length > 12;

    internal static bool IsScalar(Type type) {
        Type t = Nullable.GetUnderlyingType(type) ?? type;
        return t.IsPrimitive || t.IsEnum || t == typeof(string) || t == typeof(decimal) || t == typeof(DateTime) ||
               t == typeof(DateTimeOffset) || t == typeof(TimeSpan) || t == typeof(Guid) || t == typeof(Uri) || t == typeof(IPAddress);
    }

    private static bool IsScalarSequence(Type type) {
        if (type == typeof(string) || !typeof(IEnumerable).IsAssignableFrom(type)) return false;
        Type? element = type.IsArray
            ? type.GetElementType()
            : type.GetInterfaces().Concat(new[] { type })
                .FirstOrDefault(static i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IEnumerable<>))
                ?.GetGenericArguments()[0];
        return element != null && IsScalar(element);
    }

    private static string FormatCell(object? value) {
        if (value == null) return string.Empty;
        if (value is IEnumerable sequence && value is not string) {
            return string.Join("; ", sequence.Cast<object?>().Where(static v => v != null).Select(static v => Format(v!)));
        }
        return IsScalar(value.GetType()) ? Format(value) : string.Empty;
    }

    internal static string Format(object value) => value switch {
        string s => s.Trim(),
        bool b => b ? "Yes" : "No",
        DateTimeOffset dto => dto.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture),
        DateTime dt => (dt.Kind == DateTimeKind.Local ? dt.ToUniversalTime() : dt).ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture),
        TimeSpan ts => ts.ToString("c", CultureInfo.InvariantCulture),
        double d => d.ToString("0.##", CultureInfo.InvariantCulture),
        float f => f.ToString("0.##", CultureInfo.InvariantCulture),
        IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? string.Empty
    };

    private static readonly HashSet<string> Acronyms = new(StringComparer.OrdinalIgnoreCase) {
        "dns", "spf", "dkim", "dmarc", "mx", "tls", "ttl", "ip", "ipv4", "ipv6", "url", "uri", "http", "https", "hsts",
        "caa", "ns", "soa", "ssl", "smtp", "imap", "pop", "pop3", "rua", "ruf", "bimi", "arc", "dane", "tlsa", "rpki",
        "asn", "ct", "id", "utc", "txt", "cname", "ptr", "aaaa", "mta", "sts", "rdap", "vmc", "svg", "api", "ds", "dnskey"
    };

    /// <summary>Turns a member name such as <c>DnsLookupsCount</c> into "DNS lookups count".</summary>
    internal static string Humanize(string name) {
        var words = new List<string>();
        var current = new StringBuilder();
        for (int i = 0; i < name.Length; i++) {
            char c = name[i];
            if (c == ' ' || c == '_') {
                Flush();
                continue;
            }
            bool boundary = current.Length > 0 && char.IsUpper(c) &&
                            (char.IsLower(name[i - 1]) || char.IsDigit(name[i - 1]) || i + 1 < name.Length && char.IsLower(name[i + 1]));
            if (boundary) Flush();
            current.Append(c);
        }
        Flush();
        for (int i = 0; i < words.Count; i++) {
            string word = words[i];
            if (Acronyms.Contains(word)) words[i] = word.ToUpperInvariant();
            else if (i == 0) words[i] = char.ToUpperInvariant(word[0]) + word.Substring(1).ToLowerInvariant();
            else words[i] = word.ToLowerInvariant();
        }
        return string.Join(" ", words);

        void Flush() {
            if (current.Length > 0) words.Add(current.ToString());
            current.Clear();
        }
    }
}
