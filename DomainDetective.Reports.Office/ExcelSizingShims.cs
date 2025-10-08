// Compile-time shim so DomainDetective.Reports.Office can build against the
// published OfficeIMO.Excel package which does not include the new sizing API.
// When the local OfficeIMO.Excel project is present, USE_LOCAL_OFFICEIMO_EXCEL
// is defined (see csproj) and this file is excluded from behavior.
#if NET8_0 && !USE_LOCAL_OFFICEIMO_EXCEL
using System;
using System.Collections.Generic;

namespace OfficeIMO.Excel.Fluent
{
    /// <summary>
    /// Minimal options type to satisfy callsites when building against the published OfficeIMO.Excel package.
    /// When the local OfficeIMO.Excel project is referenced (<c>USE_LOCAL_OFFICEIMO_EXCEL</c>), this shim is excluded
    /// and the real sizing API is used instead.
    /// </summary>
    public sealed class ColumnSizingOptions
    {
        /// <summary>Width in characters for short text columns.</summary>
        public double ShortWidth { get; set; } = 16;
        /// <summary>Width in characters for numeric columns.</summary>
        public double NumericWidth { get; set; } = 10;
        /// <summary>Width in characters for medium text columns.</summary>
        public double MediumWidth { get; set; } = 28;
        /// <summary>Width in characters for long text columns.</summary>
        public double LongWidth { get; set; } = 56;

        /// <summary>Headers considered short (applies <see cref="ShortWidth"/>).</summary>
        public HashSet<string> ShortHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Headers considered numeric (applies <see cref="NumericWidth"/>).</summary>
        public HashSet<string> NumericHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Headers considered medium (applies <see cref="MediumWidth"/>).</summary>
        public HashSet<string> MediumHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Headers considered long (applies <see cref="LongWidth"/>).</summary>
        public HashSet<string> LongHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Headers that should wrap text.</summary>
        public HashSet<string> WrapHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Explicit width overrides by header name.</summary>
        public Dictionary<string, double> WidthByHeader { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// No-op extensions used when building against the OfficeIMO.Excel package without the sizing API.
    /// </summary>
    public static class SheetComposerSizingShims
    {
        /// <summary>
        /// No-op placeholder used in package builds. When the real API is available, this applies
        /// column sizing rules to the specified A1 range.
        /// </summary>
        public static SheetComposer ApplyColumnSizing(this SheetComposer composer, string? a1Range, Action<ColumnSizingOptions> configure)
        {
            // No-op on package builds
            return composer;
        }
    }
}
#endif
