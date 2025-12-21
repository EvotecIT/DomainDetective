using System;
using System.Collections.Generic;
using System.Collections;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Management.Automation.Language;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Composes a security report (Word/HTML) from pipeline view objects (SPF/DKIM/DMARC).</summary>
    /// <para>Pipe outputs from existing cmdlets to build one report without duplicating rendering logic.</para>
    /// <example>
    ///   <summary>Compose SPF+DMARC across two domains.</summary>
    ///   <code>
    ///   Test-DDEmailSpfRecord -DomainName contoso.com, fabrikam.com |
    ///   Test-DDEmailDmarcRecord -DomainName contoso.com, fabrikam.com |
    ///   Export-DDSecurityReport -ExportFormat Word -ExportPath ".\\Reports" -OpenReport
    ///   </code>
    /// </example>
    /// <example>
    ///   <summary>Inline, positional ScriptBlock (no -Compose switch).</summary>
    ///   <code>
    ///   Export-DDSecurityReport -ExportFormat Markdown -ExportPath ".\\Reports" {
    ///     Test-DDEmailSpfRecord  -DomainName contoso.com,fabrikam.com
    ///     Test-DDEmailDkimRecord -DomainName contoso.com,fabrikam.com
    ///     Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
    ///   }
    ///   </code>
    /// </example>
    /// <example>
    ///   <summary>Pipeline + inline together (pipeline binds to InputObject, block binds to Compose).</summary>
    ///   <code>
    ///   $views = Test-DDEmailSpfRecord -DomainName contoso.com,fabrikam.com
    ///   $views | Export-DDSecurityReport -ExportFormat Markdown -ExportPath ".\\Reports" {
    ///     Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
    ///   }
    ///   </code>
    /// </example>
    /// <example>
    ///   <summary>Preserve input domain order and force a custom section order.</summary>
    ///   <code>
    ///   Export-DDSecurityReport -ExportFormat Html -ExportPath ".\\Reports" -DomainOrder Input `
    ///     -SectionOrderMode Custom -SectionOrder MX,SPF,DMARC {
    ///     Test-DDEmailSpfRecord   -DomainName contoso.com,fabrikam.com
    ///     Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
    ///   }
    ///   </code>
    /// </example>
    [Cmdlet(VerbsData.Export, "DDSecurityReport", DefaultParameterSetName = "Default")]
    [Alias("New-DDSecurityReport")]
    public sealed class CmdletExportSecurityReport : ExportableAsyncPSCmdlet {
        /// <summary>Pipeline input to compose into the report.</summary>
        /// <para>Objects to compose (SPF/DKIM/DMARC/… view objects). Optional when using <c>-Compose</c>.</para>
        /// <para>Accepts single objects or arrays; enumerables are flattened. If a <see cref="ScriptBlock"/> is supplied, it is invoked and its output is composed.</para>
        // Default set: keep positional 0 for backward compatibility when no -Compose is used
        [Parameter(Mandatory = false, ValueFromPipeline = true, Position = 0, ParameterSetName = "Default")]
        // Inline set: accept pipeline as well, but place after the scriptblock
        [Parameter(Mandatory = false, ValueFromPipeline = true, Position = 1, ParameterSetName = "Inline")]
        public object? InputObject;

        /// <summary>Detail scope for section writers.</summary>
        [Parameter(Mandatory = false)]
        public DomainDetective.Reports.ReportScope Scope { get; set; } = DomainDetective.Reports.ReportScope.Normal;


        /// <summary>Include Info-level findings in sections when supported.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowInfoFindings { get; set; } = true;

        // Provider Help controls
        /// <para>Controls how much provider reference material is embedded beneath each section (MX/SPF/DKIM/DMARC, etc.).</para>
        /// <para>
        /// Presets: <c>Off</c> (no provider help), <c>Minimal</c> (only under MX, no summaries/notes),
        /// <c>Standard</c> (balanced defaults), <c>Detailed</c> (enable all summaries/notes/verified/badges under all sections).
        /// Use together with <see cref="ProviderHelpOptions"/> to fine-tune.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Off","Minimal","Standard","Detailed")]
        public string ProviderHelpPreset { get; set; } = "Standard";

        /// <para>Optional overrides for the chosen <see cref="ProviderHelpPreset"/>. Provide as a hashtable.</para>
        /// <para>
        /// Recognized keys: <c>Under</c> (array of section keys such as MX, SPF, DKIM, DMARC, BIMI, ARC),
        /// <c>Topics</c> (array of topic names to order), <c>ShowSummaries</c>, <c>ShowNotes</c>,
        /// <c>ShowBadges</c>, <c>ShowVerified</c>, <c>IncludeRestricted</c>, <c>IncludeThirdParty</c>,
        /// and <c>MaxProviders</c> (integer limit).
        /// Example: <c>@{ Under = 'MX','SPF','DKIM'; ShowNotes = $true; MaxProviders = 10 }</c>.
        /// </para>
        [Parameter(Mandatory = false)]
        public Hashtable? ProviderHelpOptions { get; set; }

        /// <summary>Inline script block used to generate additional input for composition.</summary>
        /// <para>Optional script block executed to produce additional input objects for composition (inline mode).</para>
        /// <para>Example:</para>
        /// <para>
        /// <code>
        /// Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\Reports {
        ///     Test-DDEmailSpfRecord -DomainName contoso.com
        ///     Test-DDDnsBlacklist -NameOrIpAddress 203.0.113.5
        /// }
        /// </code>
        /// </para>
        // Make Compose the first positional parameter in the Inline parameter set, so users can write:
        // Export-DDSecurityReport { Test-DDEmailSpfRecord -DomainName example.com }
        [Parameter(Mandatory = false, Position = 0, ParameterSetName = "Inline")]
        public ScriptBlock? Compose { get; set; }

        // Per-call narrative overrides (optional)
        /// <summary>Override document title for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Title { get; set; }
        /// <summary>Override document subject/description for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Subject { get; set; }
        /// <summary>Override document category for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Category { get; set; }
        /// <summary>Override document keywords (comma-separated) for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Keywords { get; set; }
        /// <summary>Override document creator/author for this export run.</summary>
        [Parameter(Mandatory = false)] public string? Creator { get; set; }

        // Presentation profiles (optional)
        /// <para>Choose the HTML presentation profile.</para>
        /// <para>
        /// <c>Document</c> provides a narrative, document-style layout; <c>Dashboard</c> focuses on
        /// high-level, concise summaries suitable for quick review or portals.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Document","Dashboard")]
        public string HtmlProfile { get; set; } = "Document";

        /// <para>Choose the Excel presentation profile.</para>
        /// <para>
        /// <c>Workbook</c> exports structured sheets intended for analysis and filtering; <c>Dashboard</c>
        /// emphasizes an at-a-glance overview sheet.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Workbook","Dashboard")]
        public string ExcelProfile { get; set; } = "Workbook";

        // Ordering controls
        /// <para>Controls how domains are ordered in the output.</para>
        /// <para>
        /// <c>Alphabetical</c> sorts domains A→Z. <c>Input</c> preserves first-seen order from the input
        /// stream/inline composition.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Alphabetical","Input")]
        public string DomainOrder { get; set; } = "Alphabetical";

        /// <para>Controls section ordering within each domain.</para>
        /// <para>
        /// <c>Canonical</c> uses the built-in order (e.g. MX, SPF, DKIM, DMARC, …), <c>Input</c> orders by
        /// first appearance in your data, and <c>Custom</c> applies the explicit order from <see cref="SectionOrder"/>.
        /// </para>
        [Parameter(Mandatory = false)]
        [ValidateSet("Canonical","Input","Custom")]
        public string SectionOrderMode { get; set; } = "Canonical";

        /// <para>Explicit section order to use when <see cref="SectionOrderMode"/> is <c>Custom</c>.</para>
        /// <para>
        /// Typical keys include: MX, SPF, DKIM, DMARC, ARC, BIMI, DNSBL, RPKI, NS, SOA, ZoneTransfer,
        /// Wildcard, CAA, Classification, MTA-STS, TLS-RPT, DNSSEC, DANE. Values are normalized (e.g. "TLSRPT" → "TLS-RPT").
        /// </para>
        [Parameter(Mandatory = false)]
        public string[]? SectionOrder { get; set; }

        /// <summary>Max status columns in the Word executive summary table.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(1, 12)]
        public int? SummaryColumnCap { get; set; }

        private readonly List<object> _items = new();

        private static readonly HashSet<string> _autoVariables = new(StringComparer.OrdinalIgnoreCase) {
            "_",
            "PSItem",
            "args",
            "PSBoundParameters",
            "MyInvocation",
            "ExecutionContext",
            "input",
            "null",
            "true",
            "false",
            "Error",
            "HOME",
            "Host",
            "PID",
            "PSCommandPath",
            "PSCulture",
            "PSHome",
            "PSScriptRoot",
            "PSSessionApplicationName",
            "PSSessionConfigurationName",
            "PSSessionOption",
            "PSUICulture",
            "PSVersionTable",
            "PWD",
            "ShellId"
        };

        private static readonly string[] _preferenceVariables = {
            "VerbosePreference",
            "DebugPreference",
            "ErrorActionPreference",
            "WarningPreference",
            "InformationPreference",
            "ProgressPreference",
            "PSDefaultParameterValues"
        };

        // Recursively append objects, executing ScriptBlocks when provided via InputObject
        private void AppendObject(object obj)
        {
            if (obj == null) return;
            object Unwrap(object o) => (o is PSObject pso && pso.BaseObject != null) ? pso.BaseObject : o;
            var o2 = Unwrap(obj);

            // If caller passed a ScriptBlock as InputObject (positional or via pipeline), execute it and append its results
            if (o2 is ScriptBlock sb)
            {
                try
                {
                    var results = sb.Invoke();
                    if (results != null)
                    {
                        foreach (var r in results) if (r != null) AppendObject(Unwrap(r));
                    }
                }
                catch (Exception ex)
                {
                    WriteWarning($"InputObject ScriptBlock failed: {ex.Message}");
                }
                return;
            }

            // Flatten enumerables (excluding strings) and process items recursively
            if (o2 is System.Collections.IEnumerable en && o2 is not string)
            {
                foreach (var e in en) if (e != null) AppendObject(Unwrap(e));
                return;
            }

            _items.Add(o2);
        }

    /// <summary>Collects pipeline inputs for composition.</summary>
    protected override Task ProcessRecordAsync() {
        if (InputObject != null) AppendObject(InputObject);
        return Task.CompletedTask;
    }

        /// <summary>Generates the report at the end of the pipeline.</summary>
        protected override async Task EndProcessingAsync() {
            // If a script block was provided, invoke and append its results
            if (Compose != null) {
                var ranParallel = false;
                if (!DisableParallel.IsPresent) {
                    try {
                        ranParallel = TryExecuteComposeInParallel(Compose, out var parallelResults);
                        if (ranParallel && parallelResults.Count > 0) {
                            foreach (var obj in parallelResults) {
                                if (obj != null) {
                                    _items.Add(obj.BaseObject ?? obj);
                                }
                            }
                        }
                    } catch (Exception ex) {
                        WriteWarning($"Compose parallel execution failed: {ex.Message}");
                    }
                }

                if (!ranParallel) {
                    try {
                        var results = Compose.Invoke();
                        if (results != null) {
                            foreach (var obj in results) if (obj != null) _items.Add(obj.BaseObject ?? obj);
                        }
                    } catch (Exception ex) {
                        WriteWarning($"Compose block failed: {ex.Message}");
                    }
                }
            }

            if (_items.Count == 0) {
                return;
            }

            var fmts = (ExportFormat != null && ExportFormat.Length > 0)
                ? ExportFormat
                : new[] { ExportDefaults.Format };
            // Flatten nested arrays/lists from pipeline variables ($spf, $dmarc, $mx)
            var flat = new List<object>();
            IEnumerable<object> Flatten(object o) {
                object Unwrap(object x) => (x is PSObject pso && pso.BaseObject != null) ? pso.BaseObject : x;
                if (o is System.Collections.IEnumerable en && o is not string) {
                    foreach (var e in en) if (e != null) yield return Unwrap(e);
                } else {
                    yield return Unwrap(o);
                }
            }
            foreach (var raw in _items) foreach (var it in Flatten(raw)) flat.Add(it);

            // Auto-collect TTL data when DKIM is present and no TTL views supplied for that domain
            try
            {
                var dkimSubjects = new HashSet<string>(flat.OfType<DomainDetective.Views.DkimRecordInfo>()
                    .Select(x => x?.Subject)
                    .Where(s => !string.IsNullOrWhiteSpace(s))!
                    .Select(s => s!), StringComparer.OrdinalIgnoreCase);
                if (dkimSubjects.Count > 0)
                {
                    var ttlPresent = new HashSet<string>(flat.OfType<DomainDetective.Views.TtlInfo>()
                        .Select(x => x?.Subject)
                        .Where(s => !string.IsNullOrWhiteSpace(s))!
                        .Select(s => s!), StringComparer.OrdinalIgnoreCase);
                    var need = dkimSubjects.Except(ttlPresent, StringComparer.OrdinalIgnoreCase).ToList();
                    if (need.Count > 0)
                    {
                        WriteVerbose($"Export-DDSecurityReport: adding TTL analysis for {need.Count} domain(s) to populate DKIM TTLs.");
                        foreach (var domain in need)
                        {
                            try
                            {
                                var ana = new DomainDetective.DnsTtlAnalysis();
                                // Provide known selectors to speed up TXT lookup
                                var sels = flat.OfType<DomainDetective.Views.DkimRecordInfo>()
                                               .Where(r => string.Equals(r?.Subject, domain, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(r?.Selector))
                                               .Select(r => r!.Selector!)
                                               .Distinct(StringComparer.OrdinalIgnoreCase)
                                               .ToList();
                                if (sels.Count > 0) ana.DkimSelectors = sels;
                                ana.Analyze(domain, new DomainDetective.InternalLogger()).GetAwaiter().GetResult();
                                var ttlView = DomainDetective.Views.Converters.Convert(ana);
                                if (ttlView != null) flat.Add(ttlView);
                            }
                            catch (Exception ex)
                            {
                                WriteVerbose($"TTL analysis for '{domain}' failed: {ex.Message}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteVerbose($"TTL auto-collection skipped due to error: {ex.Message}");
            }

            // Build label from first two domains we can detect
            var subjects = ExtractSubjects(flat);
            WriteVerbose($"Export-DDSecurityReport: composing {flat.Count} item(s) across {subjects.Count} domain(s).");
            if (IsVerboseEnabled()) {
                try {
                    var orderMode = (DomainDetective.Reports.SectionOrderMode)Enum.Parse(
                        typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true);
                    var custom = DomainDetective.Reports.SectionOrdering.NormalizeSectionList(SectionOrder ?? Array.Empty<string>());
                    var inputOrder = DomainDetective.Reports.SectionOrdering.DetermineSectionOrderByDomain(flat);
                    var grouped = DomainDetective.Reports.CompositionBuilder.GroupBySubject(flat);
                    foreach (var kv in grouped) {
                        var domain = kv.Key;
                        var b = kv.Value;
                        var present = new List<string>();
                        if (b.Mx != null) present.Add("MX");
                        if (b.Spf != null) present.Add("SPF");
                        if (b.Dkim.Count > 0) present.Add("DKIM");
                        if (b.Dmarc != null) present.Add("DMARC");
                        if (b.Arc != null) present.Add("ARC");
                        if (b.Bimi != null) present.Add("BIMI");
                        if (b.Dnsbl != null) present.Add("DNSBL");
                        if (b.Classification != null) present.Add("Classification");
                        if (b.Mtasts != null) present.Add("MTA-STS");
                        if (b.TlsRpt != null) present.Add("TLS-RPT");
                        if (b.Ns != null) present.Add("NS");
                        if (b.Soa != null) present.Add("SOA");
                        if (b.ZoneTransfer != null) present.Add("ZoneTransfer");
                        if (b.Wildcard != null) present.Add("Wildcard");
                        if (b.Caa != null) present.Add("CAA");
                        if (b.Dnssec != null) present.Add("DNSSEC");
                        if (b.Dane != null) present.Add("DANE");
                        if (b.Rpki != null) present.Add("RPKI");
                        if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null) present.Add("MAILTLS");
                        var input = inputOrder.TryGetValue(domain, out var list) ? list : null;
                        var resolved = DomainDetective.Reports.SectionOrdering.ResolveOrder(orderMode, present, input, custom);
                        if (resolved.Count > 0) {
                            WriteVerbose($"Export-DDSecurityReport: section order for {domain}: {string.Join(", ", resolved)}");
                        }
                    }
                } catch (Exception ex) {
                    WriteVerbose($"Export-DDSecurityReport: failed to compute section order: {ex.Message}");
                }
            }
            var label = subjects.Count switch {
                0 => "report",
                1 => subjects[0],
                2 => $"{subjects[0]}+{subjects[1]}",
                _ => $"{subjects[0]}+{subjects[1]}(+{subjects.Count - 2})"
            };
            // Helper to compute per-format output path when multiple formats were requested
            string ResolveOutPathForFormat(DomainDetective.Reports.ReportFormat f)
            {
                if (!string.IsNullOrWhiteSpace(ExportPath))
                {
                    try
                    {
                        var p = ExportPath!;
                        var looksLikeDirectory = false;
                        if (System.IO.Directory.Exists(p)) looksLikeDirectory = true;
                        else if (p.EndsWith(System.IO.Path.DirectorySeparatorChar.ToString()) || p.EndsWith(System.IO.Path.AltDirectorySeparatorChar.ToString())) looksLikeDirectory = true;
                        else if (!System.IO.Path.HasExtension(p)) looksLikeDirectory = true;

                        if (!looksLikeDirectory && fmts.Length > 1)
                        {
                            // User provided a file path but asked for multiple formats; derive unique paths by replacing extension
                            var dir = System.IO.Path.GetDirectoryName(p) ?? string.Empty;
                            var name = System.IO.Path.GetFileNameWithoutExtension(p);
                            var ext = f switch {
                                DomainDetective.Reports.ReportFormat.Html => ".html",
                                DomainDetective.Reports.ReportFormat.Word => ".docx",
                                DomainDetective.Reports.ReportFormat.Excel => ".xlsx",
                                DomainDetective.Reports.ReportFormat.Pdf => ".pdf",
                                DomainDetective.Reports.ReportFormat.Json => ".json",
                                DomainDetective.Reports.ReportFormat.Markdown => ".md",
                                DomainDetective.Reports.ReportFormat.MarkdownHtml => ".html",
                                _ => ".html"
                            };
                            var combined = System.IO.Path.Combine(string.IsNullOrEmpty(dir) ? "." : dir, name + ext);
                            try { System.IO.Directory.CreateDirectory(string.IsNullOrEmpty(dir) ? "." : dir); } catch { }
                            return combined;
                        }
                    }
                    catch { /* fall through to helper */ }
                }
                return DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, label, f);
            }

            try {
                var summaryColumnCap = SummaryColumnCap ?? ExportDefaults.SummaryColumnCap;
                foreach (var fmt in fmts) {
                    var outPath = ResolveOutPathForFormat(fmt);
                    switch (fmt) {
                        case DomainDetective.Reports.ReportFormat.Word:
                            var helpOpts = BuildProviderHelpOptions(ProviderHelpPreset, ProviderHelpOptions);
                            DomainDetective.Reports.Office.WordCompositionReport.Generate(
                                outPath,
                                flat,
                            Scope,
                            ShowInfoFindings.IsPresent,
                            ExportDefaults.NarrativePlacement,
                            string.IsNullOrWhiteSpace(Title) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle) : Title,
                            string.IsNullOrWhiteSpace(Subject) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject) : Subject,
                            string.IsNullOrWhiteSpace(Category) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory) : Category,
                            string.IsNullOrWhiteSpace(Keywords) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords) : Keywords,
                            string.IsNullOrWhiteSpace(Creator) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator) : Creator,
                            ExportDefaults.CompanyName,
                            ExportDefaults.CompanyAddress,
                            ExportDefaults.CompanyYear,
                            string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                            string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                            string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText,
                            true,
                            true,
                            helpOpts,
                            (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                            (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                            SectionOrder,
                            summaryColumnCap: summaryColumnCap,
                            headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                            footerLogoSizePx: ExportDefaults.FooterLogoSizePx);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                        case DomainDetective.Reports.ReportFormat.Html:
                        DomainDetective.Reports.Html.HtmlCompositionReport.Generate(
                            outPath,
                            flat,
                            Scope,
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            ExportDefaults.NarrativePlacement,
                            string.IsNullOrWhiteSpace(Title) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle) : Title,
                            string.IsNullOrWhiteSpace(Creator) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator) : Creator,
                            string.IsNullOrWhiteSpace(Subject) ? (string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject) : Subject,
                            (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                            (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                            SectionOrder,
                            (DomainDetective.Reports.Html.HtmlProfile)Enum.Parse(typeof(DomainDetective.Reports.Html.HtmlProfile), HtmlProfile, ignoreCase: true));
                        break;
                        case DomainDetective.Reports.ReportFormat.Excel:
                            DomainDetective.Reports.Office.ExcelCompositionReport.Generate(
                                outPath,
                                flat,
                                Scope,
                            new DomainDetective.Reports.OrderingOptions {
                                DomainOrder = (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                                SectionOrderMode = (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                                SectionOrder = SectionOrder
                            },
                            (DomainDetective.Reports.Office.ExcelProfile)Enum.Parse(typeof(DomainDetective.Reports.Office.ExcelProfile), ExcelProfile, ignoreCase: true));
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                        case DomainDetective.Reports.ReportFormat.Markdown:
                            DomainDetective.Reports.Markdown.MarkdownCompositionReport.Generate(
                                outPath,
                                flat,
                                Scope,
                                new DomainDetective.Reports.OrderingOptions {
                                    DomainOrder = (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                                    SectionOrderMode = (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                                    SectionOrder = SectionOrder
                                });
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                        case DomainDetective.Reports.ReportFormat.MarkdownHtml:
                            DomainDetective.Reports.Markdown.MarkdownCompositionReport.GenerateMarkdownHtml(
                                outPath,
                                flat,
                                Scope,
                                new DomainDetective.Reports.OrderingOptions {
                                    DomainOrder = (DomainDetective.Reports.DomainOrder)Enum.Parse(typeof(DomainDetective.Reports.DomainOrder), DomainOrder, ignoreCase: true),
                                    SectionOrderMode = (DomainDetective.Reports.SectionOrderMode)Enum.Parse(typeof(DomainDetective.Reports.SectionOrderMode), SectionOrderMode, ignoreCase: true),
                                    SectionOrder = SectionOrder
                                });
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        break;
                        default:
                            await ExportNotImplementedAsync("Export-DDSecurityReport");
                            return;
                    }
                }
            } catch (Exception ex) {
                WriteWarning($"Export failed: {ex.Message}");
            }

            return;
        }

        private sealed class ParallelComposePlan {
            public ParallelComposePlan(List<ParallelComposeWorkItem> items, string description) {
                Items = items;
                Description = description;
            }

            public List<ParallelComposeWorkItem> Items { get; }
            public string Description { get; }
        }

        private sealed class ParallelComposeWorkItem {
            public ParallelComposeWorkItem(string scriptText, Dictionary<string, object?> variables, int index) {
                ScriptText = scriptText;
                Variables = variables;
                Index = index;
            }

            public string ScriptText { get; }
            public Dictionary<string, object?> Variables { get; }
            public int Index { get; }
        }

        private sealed class ComposeInvocationResult {
            public int Index { get; set; }
            public List<PSObject> Output { get; set; } = new();
            public List<string> Verbose { get; set; } = new();
            public List<string> Warnings { get; set; } = new();
            public List<ErrorRecord> Errors { get; set; } = new();
            public List<InformationRecord> Information { get; set; } = new();
        }

        private bool TryExecuteComposeInParallel(ScriptBlock compose, out List<PSObject> results) {
            results = new List<PSObject>();
            var plan = BuildParallelComposePlan(compose, out var reason);
            if (plan == null) {
                if (!string.IsNullOrWhiteSpace(reason)) {
                    WriteVerbose($"Export-DDSecurityReport: Compose not parallelized ({reason}).");
                }
                return false;
            }

            var throttle = GetEffectiveThrottleLimit();
            WriteVerbose($"Export-DDSecurityReport: executing Compose in parallel ({plan.Description}, throttle {throttle}).");

            var modulePath = this.MyInvocation?.MyCommand?.Module?.Path;
            var iss = InitialSessionState.CreateDefault();
            if (!string.IsNullOrWhiteSpace(modulePath)) {
                iss.ImportPSModule(new[] { modulePath });
            }

            var min = 1;
            using var pool = RunspaceFactory.CreateRunspacePool(min, throttle, iss, this.Host);
            pool.ThreadOptions = PSThreadOptions.ReuseThread;
            pool.Open();

            var tasks = new List<Task<ComposeInvocationResult>>(plan.Items.Count);
            foreach (var item in plan.Items) {
                tasks.Add(Task.Run(() => InvokeComposeItem(pool, item)));
            }

            Task.WaitAll(tasks.ToArray());
            var ordered = tasks.Select(t => t.Result).OrderBy(r => r.Index).ToList();
            foreach (var result in ordered) {
                foreach (var message in result.Verbose) {
                    WriteVerbose(message);
                }
                foreach (var message in result.Warnings) {
                    WriteWarning(message);
                }
                foreach (var info in result.Information) {
                    WriteInformation(info);
                }
                foreach (var error in result.Errors) {
                    WriteError(error);
                }
                if (result.Output.Count > 0) {
                    results.AddRange(result.Output);
                }
            }

            return true;
        }

        private ComposeInvocationResult InvokeComposeItem(RunspacePool pool, ParallelComposeWorkItem item) {
            var result = new ComposeInvocationResult { Index = item.Index };
            using var ps = System.Management.Automation.PowerShell.Create();
            ps.RunspacePool = pool;

            foreach (var kvp in item.Variables) {
                ps.AddCommand("Set-Variable")
                    .AddParameter("Name", kvp.Key)
                    .AddParameter("Value", kvp.Value);
                ps.AddStatement();
            }

            ps.AddScript(item.ScriptText);

            try {
                var output = ps.Invoke();
                if (output != null) {
                    result.Output.AddRange(output);
                }
            } catch (Exception ex) {
                result.Warnings.Add($"Compose item failed: {ex.Message}");
            }

            if (ps.Streams.Verbose != null) {
                result.Verbose.AddRange(ps.Streams.Verbose.Select(v => v.Message));
            }
            if (ps.Streams.Warning != null) {
                result.Warnings.AddRange(ps.Streams.Warning.Select(w => w.Message));
            }
            if (ps.Streams.Information != null) {
                result.Information.AddRange(ps.Streams.Information);
            }
            if (ps.Streams.Error != null && ps.Streams.Error.Count > 0) {
                result.Errors.AddRange(ps.Streams.Error);
            }

            return result;
        }

        private ParallelComposePlan? BuildParallelComposePlan(ScriptBlock compose, out string? reason) {
            reason = null;
            if (compose.Ast is not ScriptBlockAst ast) {
                reason = "missing AST";
                return null;
            }
            if (ast.ParamBlock != null || ast.BeginBlock != null || ast.ProcessBlock != null) {
                reason = "Compose has parameters or Begin/Process blocks";
                return null;
            }
            var end = ast.EndBlock;
            if (end == null || end.Statements.Count == 0) {
                reason = "Compose is empty";
                return null;
            }

            if (end.Statements.Count == 1 && end.Statements[0] is ForEachStatementAst foreachAst) {
                return BuildForeachPlan(foreachAst, out reason);
            }

            if (end.Statements.All(s => s is PipelineAst)) {
                var items = new List<ParallelComposeWorkItem>();
                var index = 0;
                foreach (var stmt in end.Statements.Cast<PipelineAst>()) {
                    var text = stmt.Extent.Text?.Trim() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(text)) {
                        continue;
                    }
                    var vars = CollectVariables(stmt, null);
                    items.Add(new ParallelComposeWorkItem(text, vars, index++));
                }
                if (items.Count == 0) {
                    reason = "Compose contained no runnable statements";
                    return null;
                }
                return new ParallelComposePlan(items, $"statements={items.Count}");
            }

            reason = "Compose contains non-parallelizable statements";
            return null;
        }

        private ParallelComposePlan? BuildForeachPlan(ForEachStatementAst foreachAst, out string? reason) {
            reason = null;
            var varName = foreachAst.Variable?.VariablePath?.UserPath;
            if (string.IsNullOrWhiteSpace(varName)) {
                reason = "foreach variable missing";
                return null;
            }
            var varNameValue = varName!;

            var bodyText = foreachAst.Body?.Extent.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(bodyText)) {
                reason = "foreach body is empty";
                return null;
            }
            if (bodyText.StartsWith("{", StringComparison.Ordinal) && bodyText.EndsWith("}", StringComparison.Ordinal)) {
                bodyText = bodyText.Substring(1, bodyText.Length - 2).Trim();
            }
            if (string.IsNullOrWhiteSpace(bodyText)) {
                reason = "foreach body is empty";
                return null;
            }

            var collectionText = foreachAst.Condition?.Extent.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(collectionText)) {
                reason = "foreach collection is empty";
                return null;
            }

            Collection<PSObject>? values = null;
            try {
                values = this.InvokeCommand.InvokeScript(collectionText);
            } catch (Exception ex) {
                reason = $"foreach collection failed: {ex.Message}";
                return null;
            }

            if (values == null || values.Count == 0) {
                reason = "foreach collection yielded no values";
                return null;
            }

            var vars = CollectVariables(foreachAst.Body!, varNameValue);
            var items = new List<ParallelComposeWorkItem>();
            var index = 0;
            foreach (var value in values) {
                var map = new Dictionary<string, object?>(vars, StringComparer.OrdinalIgnoreCase) {
                    [varNameValue] = value?.BaseObject ?? value
                };
                items.Add(new ParallelComposeWorkItem(bodyText, map, index++));
            }
            if (items.Count == 0) {
                reason = "foreach produced no work items";
                return null;
            }
            return new ParallelComposePlan(items, $"foreach({varNameValue}) x {items.Count}");
        }

        private Dictionary<string, object?> CollectVariables(Ast ast, string? excludeVar) {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var variable in ast.FindAll(n => n is VariableExpressionAst, true).Cast<VariableExpressionAst>()) {
                var name = variable.VariablePath?.UserPath;
                if (string.IsNullOrWhiteSpace(name)) {
                    continue;
                }
                var nameValue = name!;
                if (_autoVariables.Contains(nameValue)) {
                    continue;
                }
                if (!string.IsNullOrWhiteSpace(excludeVar) && string.Equals(nameValue, excludeVar, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }
                if (nameValue.Contains(":", StringComparison.Ordinal)) {
                    continue;
                }
                names.Add(nameValue);
            }

            var vars = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in names) {
                try {
                    var val = SessionState?.PSVariable?.GetValue(name);
                    if (val != null) {
                        vars[name] = val;
                    }
                } catch { }
            }

            foreach (var pref in _preferenceVariables) {
                if (!vars.ContainsKey(pref)) {
                    try {
                        var val = SessionState?.PSVariable?.GetValue(pref);
                        if (val != null) {
                            vars[pref] = val;
                        }
                    } catch { }
                }
            }

            return vars;
        }

            private static List<string> ExtractSubjects(IEnumerable<object> items) {
                var list = new List<string>();
                IEnumerable<object> Flatten(object o) {
                    object Unwrap(object x) => (x is PSObject pso && pso.BaseObject != null) ? pso.BaseObject : x;
                    if (o is System.Collections.IEnumerable en && o is not string) {
                        foreach (var e in en) if (e != null) yield return Unwrap(e);
                    } else {
                        yield return Unwrap(o);
                    }
                }
                foreach (var raw in items ?? Array.Empty<object>()) {
                    foreach (var it in Flatten(raw)) {
                        switch (it) {
                            case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject): list.Add(mx.Subject); break;
                            case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject): list.Add(spf.Subject); break;
                            case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject): list.Add(dmarc.Subject); break;
                            case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject): list.Add(dkim.Subject); break;
                            case DomainDetective.Views.ArcInfo arc when !string.IsNullOrWhiteSpace(arc.Subject): list.Add(arc.Subject); break;
                            case DomainDetective.Views.BimiRecordInfo bimi when !string.IsNullOrWhiteSpace(bimi.Subject): list.Add(bimi.Subject); break;
                            case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject): list.Add(mc.Subject); break;
                            case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject): list.Add(ms.Subject); break;
                            case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject): list.Add(tr.Subject!); break;
                            case DomainDetective.Views.DnsblInfo db when !string.IsNullOrWhiteSpace(db.Subject): list.Add(db.Subject!); break;
                        }
                    }
                }
                return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }

        private static DomainDetective.Reports.Office.ProviderHelpRenderOptions BuildProviderHelpOptions(string preset, Hashtable? overrides)
        {
            var o = new DomainDetective.Reports.Office.ProviderHelpRenderOptions();
            switch ((preset ?? "Standard").Trim())
            {
                case "Off":
                    o.ShowUnderMx = o.ShowUnderSpf = o.ShowUnderDkim = o.ShowUnderDmarc = o.ShowUnderBimi = o.ShowUnderArc = false; break;
                case "Minimal":
                    o.ShowUnderMx = true; o.ShowUnderSpf = o.ShowUnderDkim = o.ShowUnderDmarc = o.ShowUnderBimi = o.ShowUnderArc = false;
                    o.ShowSummaries = false; o.ShowNotes = false; o.ShowVerified = false; o.ShowBadges = false;
                    break;
                case "Detailed":
                    o.ShowUnderMx = o.ShowUnderSpf = o.ShowUnderDkim = o.ShowUnderDmarc = o.ShowUnderBimi = o.ShowUnderArc = true;
                    o.ShowSummaries = true; o.ShowNotes = true; o.ShowVerified = true; o.ShowBadges = true;
                    break;
                default: // Standard
                    o.ShowUnderMx = o.ShowUnderSpf = o.ShowUnderDkim = o.ShowUnderDmarc = o.ShowUnderBimi = o.ShowUnderArc = true;
                    o.ShowSummaries = true; o.ShowNotes = true; o.ShowVerified = true; o.ShowBadges = true;
                    break;
            }
            if (overrides != null)
            {
                foreach (DictionaryEntry de in overrides)
                {
                    var key = (de.Key?.ToString() ?? string.Empty).Trim();
                    var val = de.Value;
                    if (string.Equals(key, "Under", StringComparison.OrdinalIgnoreCase) && val is System.Collections.IEnumerable en)
                    {
                        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var v in en) if (v != null) set.Add(v.ToString()!);
                        o.ShowUnderMx = set.Contains("MX");
                        o.ShowUnderSpf = set.Contains("SPF");
                        o.ShowUnderDkim = set.Contains("DKIM");
                        o.ShowUnderDmarc = set.Contains("DMARC");
                        // Optional new sections
                        try { o.ShowUnderBimi = set.Contains("BIMI"); } catch {}
                        try { o.ShowUnderArc  = set.Contains("ARC"); } catch {}
                        continue;
                    }
                    if (string.Equals(key, "Topics", StringComparison.OrdinalIgnoreCase) && val is System.Collections.IEnumerable en2)
                    {
                        var list = new List<string>();
                        foreach (var v in en2) if (v != null) list.Add(v.ToString()!.ToUpperInvariant());
                        if (list.Count > 0) o.TopicOrder = list.ToArray();
                        continue;
                    }
                    void setBool(System.Action<bool> assign)
                    {
                        if (val is bool b) assign(b);
                        else if (val is SwitchParameter sp) assign(sp.IsPresent);
                        else if (val != null && bool.TryParse(val.ToString(), out var bb)) assign(bb);
                    }
                    switch (key.ToLowerInvariant())
                    {
                        case "showsummaries": setBool(v => o.ShowSummaries = v); break;
                        case "shownotes": setBool(v => o.ShowNotes = v); break;
                        case "showbadges": setBool(v => o.ShowBadges = v); break;
                        case "showverified": setBool(v => o.ShowVerified = v); break;
                        case "includerestricted": setBool(v => o.IncludeRestricted = v); break;
                        case "includethirdparty": setBool(v => o.IncludeThirdParty = v); break;
                        case "maxproviders": if (val != null && int.TryParse(val.ToString(), out var m)) o.MaxProviders = m; break;
                    }
                }
            }
            return o;
        }
    }
}
