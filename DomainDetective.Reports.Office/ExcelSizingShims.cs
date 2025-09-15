// Compile-time shim so DomainDetective.Reports.Office can build against the
// published OfficeIMO.Excel package which does not include the new sizing API.
// When the local OfficeIMO.Excel project is present, USE_LOCAL_OFFICEIMO_EXCEL
// is defined (see csproj) and this file is excluded from behavior.
#if NET8_0 && !USE_LOCAL_OFFICEIMO_EXCEL
using System;
using System.Collections.Generic;

namespace OfficeIMO.Excel.Fluent
{
    // Minimal options type to satisfy callsites. No-op when using the package.
    public sealed class ColumnSizingOptions
    {
        public double ShortWidth { get; set; } = 16;
        public double NumericWidth { get; set; } = 10;
        public double MediumWidth { get; set; } = 28;
        public double LongWidth { get; set; } = 56;

        public HashSet<string> ShortHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> NumericHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> MediumHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> LongHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> WrapHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, double> WidthByHeader { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public static class SheetComposerSizingShims
    {
        public static SheetComposer ApplyColumnSizing(this SheetComposer composer, string? a1Range, Action<ColumnSizingOptions> configure)
        {
            // No-op on package builds
            return composer;
        }
    }
}
#endif
