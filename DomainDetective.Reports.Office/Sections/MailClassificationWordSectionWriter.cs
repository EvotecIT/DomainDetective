using System;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes a Mail Classification section (Sending/Receiving/Parked) into Word documents.
/// </summary>
public static class MailClassificationWordSectionWriter
{
    /// <summary>
    /// Writes Mail Classification section.
    /// </summary>
    /// <param name="doc">Target document.</param>
    /// <param name="info">Mail classification view.</param>
    /// <param name="domain">Subject domain.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Include Info-level findings.</param>
    public static void Write(WordDocument doc, DomainDetective.Views.MailClassificationInfo info, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (info == null) throw new ArgumentNullException(nameof(info));

        var t = doc.AddTable(4, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Classification");
        t.Rows[0].Cells[1].AddParagraph(info.Classification ?? string.Empty);
        t.Rows[1].Cells[0].AddParagraph("Confidence");
        t.Rows[1].Cells[1].AddParagraph(info.Confidence ?? string.Empty);
        t.Rows[2].Cells[0].AddParagraph("Score");
        t.Rows[2].Cells[1].AddParagraph(info.Score.ToString("0.##"));
        t.Rows[3].Cells[0].AddParagraph("Status");
        t.Rows[3].Cells[1].AddParagraph(info.Status ?? string.Empty);
    }
}
