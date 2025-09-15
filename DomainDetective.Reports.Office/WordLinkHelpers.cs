using System;
using System.Collections.Generic;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

internal static class WordLinkHelpers
{
    public static void AddReferencesList(WordDocument doc, IEnumerable<string> refs)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (refs == null) return;
        var list = doc.AddList(WordListStyle.Bulleted);
        foreach (var r in refs)
        {
            if (string.IsNullOrWhiteSpace(r)) continue;
            try
            {
                var f = DomainDetective.Reports.LinkFormatter.Format(r);
                var p = list.AddItem(string.Empty);
                try { p.AddHyperLink(f.Title, new Uri(f.Url!), addStyle: true); }
                catch { p.AddText($"{f.Title}: {f.Url}"); }
            }
            catch
            {
                list.AddItem(r);
            }
        }
    }
}

