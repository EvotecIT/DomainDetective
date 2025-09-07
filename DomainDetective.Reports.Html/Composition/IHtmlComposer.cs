using System;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Minimal abstraction over the underlying HTML generator so section writers remain engine-agnostic.
/// </summary>
/// <summary>
/// Minimal abstraction over HTML generation so report sections remain engine-agnostic.
/// </summary>
public interface IHtmlComposer : IDisposable
{
    /// <summary>Sets metadata for the HTML document.</summary>
    /// <param name="title">Document title.</param>
    /// <param name="author">Author string.</param>
    /// <param name="description">Short description.</param>
    void SetMetadata(string? title = null, string? author = null, string? description = null);

    /// <summary>Adds a heading element.</summary>
    /// <param name="text">Heading text.</param>
    /// <param name="level">Heading level (1..6).</param>
    void AddHeading(string text, int level = 1);

    /// <summary>Adds a paragraph.</summary>
    /// <param name="text">Paragraph content.</param>
    void AddParagraph(string text);

    /// <summary>Adds a bulleted list.</summary>
    /// <param name="items">Items to include.</param>
    void AddList(System.Collections.Generic.IEnumerable<string> items);

    /// <summary>Adds a two-column key/value grid line.</summary>
    /// <param name="key">Key label.</param>
    /// <param name="value">Value text.</param>
    void AddKeyValue(string key, string value);

    /// <summary>Adds a table from anonymous/object rows.</summary>
    /// <typeparam name="T">Row type.</typeparam>
    /// <param name="rows">Rows to render.</param>
    void AddTable<T>(System.Collections.Generic.IEnumerable<T> rows);

    /// <summary>Saves the HTML document to disk.</summary>
    /// <param name="path">Target path.</param>
    /// <param name="openInBrowser">Whether to open with the default handler.</param>
    void Save(string path, bool openInBrowser = false);
}
