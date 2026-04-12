using System;
using System.Linq;
using HtmlForgeX;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Adapter implementing <see cref="IHtmlComposer"/> on top of HtmlForgeX.
/// Keep changes local here as HtmlForgeX evolves.
/// </summary>
public sealed class HtmlForgeXComposer : IHtmlComposer
{
    private readonly Document _doc;
    private TablerPage? _page;

    /// <summary>Initializes a new instance of the HtmlForgeXComposer class.</summary>
    public HtmlForgeXComposer()
    {
        _doc = new Document { LibraryMode = LibraryMode.Online, ThemeMode = ThemeMode.Light };
    }

    /// <inheritdoc />
    public void SetMetadata(string? title = null, string? author = null, string? description = null)
    {
        _doc.Head.Title = title ?? _doc.Head.Title ?? "Report";
        if (!string.IsNullOrWhiteSpace(author)) _doc.Head.Author = author;
        if (!string.IsNullOrWhiteSpace(description)) _doc.Head.Description = description;
    }

    private TablerPage EnsurePage()
    {
        if (_page != null) return _page;
        _doc.Body.Page(p => { p.Layout = TablerLayout.Fluid; _page = p; });
        return _page!;
    }

    /// <inheritdoc />
    public void AddHeading(string text, int level = 1)
    {
        var page = EnsurePage();
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
        {
            switch (level)
            {
                case 1: c.H1(text); break;
                case 2: c.H2(text); break;
                case 3: c.H3(text); break;
                case 4: c.H4(text); break;
                default: c.H5(text); break;
            }
        }));
    }

    /// <inheritdoc />
    public void AddParagraph(string text)
    {
        var page = EnsurePage();
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => c.Text(text)));
    }

    /// <summary>
    /// Adds a bulleted list within a simple card for consistent spacing.
    /// </summary>
    /// <inheritdoc />
    public void AddList(System.Collections.Generic.IEnumerable<string> items)
    {
        var vals = (items ?? Array.Empty<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
        if (vals.Count == 0) return;
        var page = EnsurePage();
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
        {
            c.Card(card =>
            {
                card.Body(b => b.AddList(l => l.WithItems(it => { foreach (var v in vals) it.Item(v); })));
            });
        }));
    }

    /// <inheritdoc />
    public void AddKeyValue(string key, string value)
    {
        var page = EnsurePage();
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => c.DataGrid(g => g.AddItem(key, value))));
    }

    /// <inheritdoc />
    public void AddTable<T>(System.Collections.Generic.IEnumerable<T> rows)
    {
        var page = EnsurePage();
        var list = rows?.ToList() ?? new System.Collections.Generic.List<T>();
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
        {
            var table = (TablerTable)c.Table(list, TableType.Tabler);
            table.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
        }));
    }

    /// <inheritdoc />
    public void Save(string path, bool openInBrowser = false)
    {
        _doc.Save(path, openInBrowser);
    }

    /// <summary>Releases resources used by this instance.</summary>
    public void Dispose()
    {
        _page = null;
        _doc?.Dispose();
    }
}
