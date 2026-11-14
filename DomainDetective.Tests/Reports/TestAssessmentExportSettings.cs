using System.Reflection;
using DomainDetective.PowerShell;
using DomainDetective.Reports;
using DomainDetective.Views;

namespace DomainDetective.Tests.Reports;

[Collection("ExportDefaults")]
public class TestAssessmentExportSettings {
    [Theory]
    [InlineData("Creator")]
    [InlineData("Subject")]
    [InlineData("Category")]
    [InlineData("Keywords")]
    [InlineData("CompanyName")]
    [InlineData("CompanyAddress")]
    [InlineData("CompanyYear")]
    [InlineData("LogoPath")]
    [InlineData("HeaderText")]
    [InlineData("FooterText")]
    [InlineData("WatermarkText")]
    [InlineData("HeaderLogoSizePx")]
    [InlineData("FooterLogoSizePx")]
    [InlineData("SummaryColumnCap")]
    [InlineData("Scope")]
    [InlineData("NarrativePlacement")]
    [InlineData("ExcelProfile")]
    [InlineData("SectionOrderMode")]
    [InlineData("SectionOrder")]
    [InlineData("ProviderHelpOptions")]
    public async Task RetiredSettingsRejectBatchBeforeCreatingOutputDirectory(string setting) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-options-" + Guid.NewGuid().ToString("N"));
        var request = new CompositionExportRequest {
            Items = new object[] { new SpfRecordInfo { Subject = "example.test" } },
            Formats = new[] { ReportFormat.Html, ReportFormat.Word, ReportFormat.Pdf, ReportFormat.Excel, ReportFormat.Markdown },
            ExportPath = Path.Combine(directory, "report.html"), AutoCollectTtl = false
        };
        ApplyUnsupported(request, setting);
        var error = await Assert.ThrowsAsync<NotSupportedException>(() => CompositionExportService.ExportAsync(request));
        Assert.Contains(setting, error.Message);
        Assert.False(Directory.Exists(directory), "Invalid options must fail before resolving output paths or writing any format.");
    }

    [Fact]
    public async Task SupportedTitleDomainOrderAndGenerationTimeSurviveExport() {
        string directory = Path.Combine(Path.GetTempPath(), "dd-options-supported-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "report.json");
        var generated = new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero);
        try {
            var result = await CompositionExportService.ExportAsync(new CompositionExportRequest {
                Items = new object[] { new SpfRecordInfo { Subject = "b.example" }, new SpfRecordInfo { Subject = "a.example" } },
                Formats = new[] { ReportFormat.Json }, ExportPath = path, AutoCollectTtl = false,
                Title = "Assessment option contract", GeneratedAtUtc = generated,
                Ordering = new OrderingOptions { DomainOrder = DomainOrder.Input },
                SummaryColumnCap = 4, ProviderHelpOptions = new ProviderHelpRenderOptions()
            });
            Assert.True(Assert.Single(result.Reports).Success);
            var report = DomainAssessmentJson.Deserialize(File.ReadAllText(path))!;
            Assert.Equal("Assessment option contract", report.Title);
            Assert.Equal(generated, report.GeneratedAtUtc);
            Assert.Equal(new[] { "b.example", "a.example" }, report.Domains.Select(domain => domain.Domain));
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }

    [Fact]
    public async Task ServiceRejectsUnsupportedSettingsWithoutOverwritingExistingReport() {
        string path = Path.Combine(Path.GetTempPath(), "dd-options-sentinel-" + Guid.NewGuid().ToString("N") + ".md");
        File.WriteAllText(path, "existing report");
        try {
            var request = new CompositionExportRequest {
                WatermarkText = "Confidential", ExportPath = path, Formats = new[] { ReportFormat.Markdown },
                Items = new object[] { new SpfRecordInfo { Subject = "example.test" } }, AutoCollectTtl = false
            };
            var error = await Assert.ThrowsAsync<NotSupportedException>(() => CompositionExportService.ExportAsync(request));
            Assert.Contains("WatermarkText", error.Message);
            Assert.Equal("existing report", File.ReadAllText(path));
        } finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("IncludeTechnicalDetails")]
    [InlineData("IncludeRecommendations")]
    [InlineData("IncludeRawData")]
    [InlineData("Theme")]
    [InlineData("TemplateName")]
    [InlineData("CustomProperties")]
    public async Task GeneralReportOptionsRejectUnsupportedOverridesBeforeWrite(string setting) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-general-options-" + Guid.NewGuid().ToString("N"));
        var options = new ReportOptions { Format = ReportFormat.Word, OutputPath = Path.Combine(directory, "report.docx") };
        if (setting == "CustomProperties") { options.CustomProperties["Creator"] = "Fixture author"; }
        else {
            var property = typeof(ReportOptions).GetProperty(setting)!;
            property.SetValue(options, setting == "Theme" ? ReportTheme.Dark : setting == "TemplateName" ? (object)"Legacy" : setting == "IncludeRawData");
        }
        using var health = new DomainHealthCheck();
        var error = await Assert.ThrowsAsync<NotSupportedException>(() => new ReportDispatcher().GenerateAsync(health, options, "example.test"));
        Assert.Contains(setting, error.Message);
        Assert.False(Directory.Exists(directory));
    }

    [Fact]
    public void PowerShellHelperRejectsInheritedBrandingBeforeWrite() {
        string directory = Path.Combine(Path.GetTempPath(), "dd-helper-options-" + Guid.NewGuid().ToString("N"));
        string previous = ExportDefaults.WatermarkText;
        try {
            ExportDefaults.WatermarkText = "Confidential";
            var error = Assert.Throws<NotSupportedException>(() => CompositionExportHelper.WriteReports(
                new object[] { new SpfRecordInfo { Subject = "example.test" } }, new[] { ReportFormat.Html, ReportFormat.Word, ReportFormat.Pdf },
                Path.Combine(directory, "report.html"), "example.test", ReportScope.Normal, "Assessment", false, null, out _));
            Assert.Contains("WatermarkText", error.Message);
            Assert.False(Directory.Exists(directory));
        } finally { ExportDefaults.WatermarkText = previous; }
    }

    [Theory]
    [InlineData("Scope")]
    [InlineData("ExcelProfile")]
    [InlineData("SectionOrderMode")]
    [InlineData("ProviderHelpPreset")]
    [InlineData("Creator")]
    public void ExportCmdletRejectsExplicitRetiredSettingsBeforeComposition(string setting) {
        var cmdlet = new CmdletExportSecurityReport();
        var property = typeof(CmdletExportSecurityReport).GetProperty(setting)!;
        property.SetValue(cmdlet, setting == "Scope" ? ReportScope.Detailed
            : setting == "ExcelProfile" ? (object)"Dashboard" : setting == "SectionOrderMode" ? "Input"
            : setting == "ProviderHelpPreset" ? "Off" : "Fixture author");
        var error = Assert.Throws<NotSupportedException>(() => cmdlet.CreateExportSettings());
        Assert.Contains(setting, error.Message);
    }

    [Fact]
    public void SetExportOptionsRejectsWholeCandidateBeforeChangingDefaults() {
        ReportFormat previous = ExportDefaults.Format;
        var cmdlet = new CmdletSetExportOptions { DefaultFormat = ReportFormat.Pdf, WatermarkText = "Confidential" };
        var process = typeof(CmdletSetExportOptions).GetMethod("ProcessRecord", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var invocation = Assert.Throws<TargetInvocationException>(() => process.Invoke(cmdlet, null));
        var error = Assert.IsType<NotSupportedException>(invocation.InnerException);
        Assert.Contains("WatermarkText", error.Message);
        Assert.Equal(previous, ExportDefaults.Format);
    }

    [Theory]
    [InlineData(ReportFormat.Word, ".docx")]
    [InlineData(ReportFormat.Pdf, ".pdf")]
    [InlineData(ReportFormat.Excel, ".xlsx")]
    public async Task DomainHealthRejectsInheritedBrandingAtEntryBeforeNetworkOrArtifacts(ReportFormat format, string extension) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-health-preflight-" + Guid.NewGuid().ToString("N"));
        string previous = ExportDefaults.WatermarkText;
        try {
            ExportDefaults.WatermarkText = "Confidential";
            var cmdlet = new CmdletTestDomainHealth {
                DomainName = new[] { "example.test" }, ExportFormat = new[] { format },
                ExportPath = Path.Combine(directory, "report" + extension),
                ExportArtifacts = new System.Management.Automation.SwitchParameter(true),
                ArtifactsDirectory = Path.Combine(directory, "artifacts")
            };
            var process = typeof(CmdletTestDomainHealth).GetMethod("ProcessRecordAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
            var error = await Assert.ThrowsAsync<NotSupportedException>(() => (Task)process.Invoke(cmdlet, null)!);
            Assert.Contains("WatermarkText", error.Message);
            Assert.False(Directory.Exists(directory), "Presentation validation must precede report paths, artifacts and domain verification.");
        } finally { ExportDefaults.WatermarkText = previous; }
    }

    [Theory]
    [InlineData("SPF", ReportFormat.Html)]
    [InlineData("DMARC", ReportFormat.Html)]
    [InlineData("DKIM", ReportFormat.Html)]
    [InlineData("ARC", ReportFormat.Html)]
    [InlineData("SPF", ReportFormat.Pdf)]
    [InlineData("DMARC", ReportFormat.Pdf)]
    [InlineData("DKIM", ReportFormat.Pdf)]
    [InlineData("ARC", ReportFormat.Pdf)]
    [InlineData("MTA-STS", ReportFormat.Pdf)]
    [InlineData("TLS-RPT", ReportFormat.Pdf)]
    [InlineData("Mail TLS", ReportFormat.Pdf)]
    [InlineData("RPKI", ReportFormat.Pdf)]
    [InlineData("Classification", ReportFormat.Pdf)]
    public async Task MailCmdletFinalizationExportsCollectedViewsWithSupportedScope(string caller, ReportFormat format) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-mail-finalize-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, format == ReportFormat.Pdf ? "report.pdf" : "report.html");
        bool previousOpen = ExportDefaults.OpenInBrowser;
        var finding = new[] { new Assessment { Severity = AssessmentSeverity.Warning, Code = "EXPORT.CALLER", Message = caller + " caller finding" } };
        ExportableAsyncPSCmdlet cmdlet;
        object view;
        switch (caller) {
            case "SPF": cmdlet = new CmdletTestSpfRecord(); view = new SpfRecordInfo { Subject = "example.test", Check = HealthCheckType.SPF, Assessments = finding }; break;
            case "DMARC": cmdlet = new CmdletTestDmarcRecord(); view = new DmarcRecordInfo { Subject = "example.test", Check = HealthCheckType.DMARC, Assessments = finding }; break;
            case "DKIM": cmdlet = new CmdletTestDkimRecord(); view = new DkimRecordInfo { Subject = "example.test", Check = HealthCheckType.DKIM, Assessments = finding }; break;
            case "ARC": cmdlet = new CmdletTestArc(); view = new ArcInfo { Subject = "example.test", Check = HealthCheckType.ARC, Assessments = finding }; break;
            case "MTA-STS": cmdlet = new CmdletTestMtaSts(); view = new MtastsInfo { Subject = "example.test", Check = HealthCheckType.MTASTS, Assessments = finding }; break;
            case "TLS-RPT": cmdlet = new CmdletTestTlsRptRecord(); view = new TlsRptInfo { Subject = "example.test", Check = HealthCheckType.TLSRPT, Assessments = finding }; break;
            case "Mail TLS": cmdlet = new CmdletTestEmailProtocolTls(); view = new MailTlsInfo { Subject = "example.test", Check = HealthCheckType.SMTPTLS, Servers = Array.Empty<MailTlsServerInfo>(), Assessments = finding }; break;
            case "RPKI": cmdlet = new CmdletTestRpki(); view = new RpkiInfo { Subject = "example.test", Check = HealthCheckType.RPKI, Assessments = finding }; break;
            default: cmdlet = new CmdletTestMailDomainClassification(); view = new MailClassificationInfo { Subject = "example.test", Check = HealthCheckType.MAILCLASSIFICATION, Assessments = finding }; break;
        }
        try {
            ExportDefaults.OpenInBrowser = false;
            cmdlet.ExportFormat = new[] { format };
            cmdlet.ExportPath = path;
            // Exercise each real finalizer with already-collected views, without invoking its network analysis phase.
            var items = Assert.IsType<List<object>>(cmdlet.GetType().GetField("_items", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(cmdlet));
            items.Add(view);
            var finalize = cmdlet.GetType().GetMethod("EndProcessingAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
            await (Task)finalize.Invoke(cmdlet, null)!;
            string text = ReportArtifactText.Read(path);
            Assert.Contains("example.test", text);
            Assert.Contains(caller + " caller finding", text);
            Assert.Single(Directory.GetFiles(directory));
        } finally {
            ExportDefaults.OpenInBrowser = previousOpen;
            if (Directory.Exists(directory)) { Directory.Delete(directory, true); }
        }
    }

    [Fact]
    public async Task StoppedMailCmdletFinalizerForwardsCancellationBeforeWritingPaperArtifacts() {
        string directory = Path.Combine(Path.GetTempPath(), "dd-mail-cancel-" + Guid.NewGuid().ToString("N"));
        bool previousOpen = ExportDefaults.OpenInBrowser;
        using var cmdlet = new CmdletTestSpfRecord {
            ExportFormat = new[] { ReportFormat.Word, ReportFormat.Pdf },
            ExportPath = Path.Combine(directory, "report.docx")
        };
        try {
            ExportDefaults.OpenInBrowser = false;
            var items = Assert.IsType<List<object>>(typeof(CmdletTestSpfRecord)
                .GetField("_items", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(cmdlet));
            items.Add(new SpfRecordInfo { Subject = "example.test", Check = HealthCheckType.SPF, SpfRecord = "v=spf1 -all" });
            typeof(AsyncPSCmdlet).GetMethod("StopProcessing", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(cmdlet, null);
            Assert.True(cmdlet.CancelToken.IsCancellationRequested);
            var finalize = typeof(CmdletTestSpfRecord).GetMethod("EndProcessingAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;

            var error = await Record.ExceptionAsync(async () => await (Task)finalize.Invoke(cmdlet, null)!);

            Assert.NotNull(error);
            Assert.IsAssignableFrom<OperationCanceledException>(error!.GetBaseException());
            Assert.Empty(Directory.Exists(directory) ? Directory.GetFiles(directory) : Array.Empty<string>());
        } finally {
            ExportDefaults.OpenInBrowser = previousOpen;
            if (Directory.Exists(directory)) { Directory.Delete(directory, true); }
        }
    }

    private static void ApplyUnsupported(CompositionExportRequest request, string setting) {
        if (setting == "Scope") { request.Scope = ReportScope.Detailed; }
        else if (setting == "NarrativePlacement") { request.NarrativePlacement = NarrativePlacement.Global; }
        else if (setting == "ExcelProfile") { request.ExcelProfile = "Dashboard"; }
        else if (setting == "SectionOrderMode") { request.Ordering.SectionOrderMode = SectionOrderMode.Input; }
        else if (setting == "SectionOrder") { request.Ordering.SectionOrder = new[] { "DMARC", "SPF" }; }
        else if (setting == "ProviderHelpOptions") { request.ProviderHelpOptions = new ProviderHelpRenderOptions { ShowSummaries = false }; }
        else {
            var property = typeof(CompositionExportRequest).GetProperty(setting)!;
            property.SetValue(request, property.PropertyType == typeof(string) ? (object)"custom setting" : setting == "SummaryColumnCap" ? 6 : 32);
        }
    }
}
