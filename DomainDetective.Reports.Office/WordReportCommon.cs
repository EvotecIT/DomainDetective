using System;
using System.IO;
using System.Linq;
using OfficeIMO.Word;
using DocumentFormat.OpenXml.Wordprocessing;

namespace DomainDetective.Reports.Office;

internal static class WordReportCommon
{
    public static void ApplyBuiltInProperties(WordDocument doc, string? title = null, string? subject = null, string? keywords = null, string? category = null, string? creator = null)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (!string.IsNullOrWhiteSpace(title)) doc.BuiltinDocumentProperties.Title = title;
        if (!string.IsNullOrWhiteSpace(subject)) doc.BuiltinDocumentProperties.Subject = subject;
        if (!string.IsNullOrWhiteSpace(keywords)) doc.BuiltinDocumentProperties.Keywords = keywords;
        if (!string.IsNullOrWhiteSpace(category)) doc.BuiltinDocumentProperties.Category = category;
        if (!string.IsNullOrWhiteSpace(creator)) doc.BuiltinDocumentProperties.Creator = creator;
    }

    public static void ApplyNarrativeProperties(WordDocument doc, object narrative, string defaultTitle, string defaultSubject, string? defaultCategory = null, string? defaultKeywords = null, string? defaultCreator = null)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (narrative == null) throw new ArgumentNullException(nameof(narrative));
        string title = ResolveStringProperty(narrative, "Title") ?? defaultTitle;
        string subject = ResolveStringProperty(narrative, "Subtitle") ?? defaultSubject;
        string? category = ResolveStringProperty(narrative, "Category") ?? defaultCategory;
        string? keywords = ResolveStringProperty(narrative, "Keywords") ?? defaultKeywords;
        string? creator = ResolveStringProperty(narrative, "Creator") ?? defaultCreator;
        ApplyBuiltInProperties(doc, title, subject, keywords, category, creator);
    }

    public static void ApplyCompanyBranding(WordDocument doc, string? companyName, string? companyAddress, string? companyYear)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        var pairs = BuildCompanyProperties(companyName, companyAddress, companyYear);
        if (pairs.Count == 0) return;
        var asObjects = new System.Collections.Generic.Dictionary<string, object>(System.StringComparer.OrdinalIgnoreCase);
        foreach (var kv in pairs) asObjects[kv.Key] = kv.Value;
        ApplyCustomProperties(doc, asObjects);
    }

    public static string ResolveHeaderLeftText(string? overrideText, object narrative, string defaultTitle)
    {
        if (!string.IsNullOrWhiteSpace(overrideText)) return overrideText!;
        var title = ResolveStringProperty(narrative, "Title");
        return string.IsNullOrWhiteSpace(title) ? defaultTitle : title!;
    }

    private static string? ResolveStringProperty(object obj, string name)
    {
        try {
            var prop = obj.GetType().GetProperty(name, System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
            if (prop == null) return null;
            var val = prop.GetValue(obj) as string;
            return string.IsNullOrWhiteSpace(val) ? null : val;
        } catch {
            return null;
        }
    }

    public static System.Collections.Generic.Dictionary<string, string> BuildCompanyProperties(string? name, string? address, string? year)
    {
        var dict = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(name)) dict["CompanyName"] = name!;
        if (!string.IsNullOrWhiteSpace(address)) dict["CompanyAddress"] = address!;
        if (!string.IsNullOrWhiteSpace(year)) dict["CompanyYear"] = year!;
        var parts = new System.Collections.Generic.List<string>();
        if (!string.IsNullOrWhiteSpace(name)) parts.Add(name!);
        if (!string.IsNullOrWhiteSpace(address)) parts.Add("| " + address!);
        if (!string.IsNullOrWhiteSpace(year)) parts.Add(year!);
        var line = string.Join(" ", parts);
        if (!string.IsNullOrWhiteSpace(line)) dict["CompanyLine"] = line;
        return dict;
    }

    public static void ApplyCustomProperties(WordDocument doc, System.Collections.Generic.IDictionary<string, object>? custom)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (custom == null || custom.Count == 0) return;
        foreach (var kv in custom)
        {
            if (kv.Value == null) continue;
            try
            {
                if (doc.CustomDocumentProperties.ContainsKey(kv.Key))
                {
                    SetCustomPropertyValue(doc.CustomDocumentProperties[kv.Key], kv.Value);
                }
                else
                {
                    var prop = CreateCustomProperty(kv.Value);
                    doc.CustomDocumentProperties.Add(kv.Key, prop);
                }
            }
            catch { /* ignore invalid names or unsupported types */ }
        }
    }

    private static WordCustomProperty CreateCustomProperty(object value)
    {
        switch (value)
        {
            case bool b:
                return new WordCustomProperty(b);
            case DateTime dt:
                return new WordCustomProperty { Value = dt };
            case DateTimeOffset dto:
                return new WordCustomProperty { Value = dto.UtcDateTime };
            case int i:
                return new WordCustomProperty { Value = i };
            case long l:
                return new WordCustomProperty { Value = l };
            case double d:
                return new WordCustomProperty { Value = d };
            case float f:
                return new WordCustomProperty { Value = (double)f };
            default:
                return new WordCustomProperty(value.ToString());
        }
    }

    private static void SetCustomPropertyValue(WordCustomProperty prop, object value)
    {
        switch (value)
        {
            case bool b:
                prop.Value = b; break;
            case DateTime dt:
                prop.Value = dt; break;
            case DateTimeOffset dto:
                prop.Value = dto.UtcDateTime; break;
            case int i:
                prop.Value = i; break;
            case long l:
                prop.Value = l; break;
            case double d:
                prop.Value = d; break;
            case float f:
                prop.Value = (double)f; break;
            default:
                prop.Value = value?.ToString(); break;
        }
    }

    public static void AddHeader(WordDocument doc, string leftText, string? rightText = null, string? logoPath = null, string? watermarkText = null)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));

        doc.AddHeadersAndFooters();
        doc.DifferentFirstPage = false;

        var headerTable = doc.Header.Default.AddTable(1, 2, WordTableStyle.TableNormal);
        headerTable.WidthType = TableWidthUnitValues.Pct;
        headerTable.Width = 5000; // 100%

        var leftP = headerTable.Rows[0].Cells[0].AddParagraph(leftText ?? string.Empty);
        if (!string.IsNullOrWhiteSpace(logoPath) && File.Exists(logoPath))
        {
            headerTable.Rows[0].Cells[0].AddParagraph().AddImage(logoPath, 48, 48);
        }
        var rightP = headerTable.Rows[0].Cells[1].AddParagraph(rightText ?? string.Empty);
        rightP.ParagraphAlignment = JustificationValues.Right;

        if (!string.IsNullOrWhiteSpace(watermarkText))
        {
            doc.Sections[0].Header.Default.AddWatermark(WordWatermarkStyle.Text, watermarkText);
        }
    }
}
