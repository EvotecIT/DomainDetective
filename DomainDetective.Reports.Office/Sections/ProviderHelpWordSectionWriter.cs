using System;
using System.Collections.Generic;
using OfficeIMO.Word;
using System.Linq;

namespace DomainDetective.Reports.Office;

internal static class ProviderHelpWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, IReadOnlyList<DomainDetective.Views.ProviderHelpLinks> help, ProviderHelpRenderOptions? opts = null)
    {
        opts ??= new ProviderHelpRenderOptions();
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (help == null || help.Count == 0) return;
        bool any = false;
        foreach (var h in help) { if (h != null && h.HasAny) { any = true; break; } }
        if (!any) return;

        headings.AddItem("Provider Help", baseLevel);
        doc.AddParagraph("Official provider documentation for configuring and troubleshooting core email controls:");

        int shown = 0;
        foreach (var ph in help)
        {
            if (ph == null || !ph.HasAny) continue;
            if (shown >= opts.MaxProviders) break;
            doc.AddParagraph(ph.ProviderName).SetBold();
            var topics = ph.Topics ?? new System.Collections.Generic.List<DomainDetective.Views.ProviderHelpTopic>();
            if (topics.Count == 0)
            {
                // Fallback to legacy url-only properties
                topics = new System.Collections.Generic.List<DomainDetective.Views.ProviderHelpTopic>();
            }
            // Reorder and filter topics
            var ordered = opts.TopicOrder?.Length > 0
                ? topics.OrderBy(t => Array.IndexOf(opts.TopicOrder, (t?.Topic ?? string.Empty).ToUpperInvariant())).ToList()
                : topics.ToList();
            if (!opts.IncludeRestricted) ordered = ordered.Where(t => (t?.IsPublic ?? true)).ToList();
            if (!opts.IncludeThirdParty) ordered = ordered.Where(t => !(t?.IsThirdParty ?? false)).ToList();
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var t in ordered)
            {
                AddTopic(list, ph.ProviderName, t, opts);
            }
            shown++;
        }
    }

    private static void AddLink(WordList list, string label, string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return;
        var linkUrl = url!;
        try
        {
            var p = list.AddItem(label + ": ");
            // Proper, clickable hyperlink with hyperlink style
            p.AddHyperLink(linkUrl, new Uri(linkUrl), addStyle: true);
        }
        catch
        {
            // Fallback to plain text if the URL is malformed
            list.AddItem(label + ": " + url);
        }
    }

    private static void AddTopic(WordList list, string providerName, DomainDetective.Views.ProviderHelpTopic? topic, ProviderHelpRenderOptions opts)
    {
        var url = topic?.Url;
        if (topic == null || string.IsNullOrWhiteSpace(url)) return;
        var text = string.IsNullOrWhiteSpace(topic.Title) ? ($"{providerName} — {topic.Topic}") : topic.Title!;
        try
        {
            var p = list.AddItem(string.Empty);
            p.AddHyperLink(text, new Uri(url), addStyle: true);
            // Append brief summary/notes and badges
            var fragments = new System.Collections.Generic.List<string>();
            if (opts.ShowSummaries && !string.IsNullOrWhiteSpace(topic.Summary)) fragments.Add(topic.Summary!);
            if (opts.ShowBadges && !topic.IsPublic) fragments.Add("[Requires login]");
            if (opts.ShowBadges && topic.IsThirdParty) fragments.Add("[Third‑party]");
            if (opts.ShowVerified && topic.LastVerified.HasValue && topic.LastVerified.Value != System.DateTime.MinValue) fragments.Add($"Verified: {topic.LastVerified.Value:yyyy-MM-dd}");
            if (opts.ShowNotes && !string.IsNullOrWhiteSpace(topic.Notes)) fragments.Add(topic.Notes!);
            if (fragments.Count > 0)
            {
                p.AddText(" — " + string.Join(" · ", fragments));
            }
        }
        catch
        {
            // Fallback single-line item
            var label = string.IsNullOrWhiteSpace(text) ? (providerName + " — " + (topic.Topic ?? "Doc")) : text;
            list.AddItem(label + ": " + url);
        }
    }
}
