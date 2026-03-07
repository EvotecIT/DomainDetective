using System;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
    private static Action<SheetComposer.ColumnComposer>? BuildDesiredStateBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.DesiredState == null)
        {
            return null;
        }

        var projection = DomainDetective.Reports.SectionProjectors.BuildDesiredState(bucket.DesiredState);
        if (projection == null)
        {
            return null;
        }

        return column =>
        {
            column.Section("Desired State");
            column.KeyValues(new (string, object?)[]
            {
                ("Mode", projection.Mode),
                ("Conforms", projection.Conforms ? "Yes" : "No"),
                ("Desired Warnings", projection.DesiredWarningCount),
                ("Desired Errors", projection.DesiredErrorCount),
                ("Best-Practice Warnings", projection.BestPracticeWarningCount),
                ("Best-Practice Errors", projection.BestPracticeErrorCount)
            });

            if (projection.DesiredFindings.Count > 0)
            {
                var rows = projection.DesiredFindings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                var range = column.TableFrom(rows, title: "Desired State Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.Add("Severity");
                    opt.MediumHeaders.UnionWith(new[] { "Code", "Target" });
                    opt.LongHeaders.Add("Message");
                    opt.WrapHeaders.Add("Message");
                });
            }

            if (projection.DesiredRecommendations.Count > 0)
            {
                var rows = projection.DesiredRecommendations.Select(r => new { r.Code, r.Title, r.How }).ToList();
                var range = column.TableFrom(rows, title: "Desired State Recommendations", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.MediumHeaders.UnionWith(new[] { "Code", "Title" });
                    opt.LongHeaders.Add("How");
                    opt.WrapHeaders.Add("How");
                });
            }

            if (!projection.IsBaselineOnly && projection.BestPracticeFindings.Count > 0)
            {
                var rows = projection.BestPracticeFindings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                var range = column.TableFrom(rows, title: "Best-Practice Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.Add("Severity");
                    opt.MediumHeaders.UnionWith(new[] { "Code", "Target" });
                    opt.LongHeaders.Add("Message");
                    opt.WrapHeaders.Add("Message");
                });
            }

            if (!projection.IsBaselineOnly && projection.BestPracticeRecommendations.Count > 0)
            {
                var rows = projection.BestPracticeRecommendations.Select(r => new { r.Code, r.Title, r.How }).ToList();
                var range = column.TableFrom(rows, title: "Best-Practice Recommendations", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.MediumHeaders.UnionWith(new[] { "Code", "Title" });
                    opt.LongHeaders.Add("How");
                    opt.WrapHeaders.Add("How");
                });
            }
        };
    }
}
