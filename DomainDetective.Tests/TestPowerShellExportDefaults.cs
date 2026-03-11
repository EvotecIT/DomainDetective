using System.Collections;
using DomainDetective.PowerShell;
using DomainDetective.Reports;

namespace DomainDetective.Tests;

[Collection("ExportDefaults")]
public class TestPowerShellExportDefaults
{
    [Fact]
    public void ExportSecurityReportDefaultsToShowingInfoFindings()
    {
        var actual = CmdletExportSecurityReport.ResolveShowInfoFindings(
            new System.Management.Automation.SwitchParameter(false),
            new Hashtable());

        Assert.True(actual);
    }

    [Fact]
    public void ExportSecurityReportHonorsExplicitFalseForInfoFindings()
    {
        var actual = CmdletExportSecurityReport.ResolveShowInfoFindings(
            new System.Management.Automation.SwitchParameter(false),
            new Hashtable { { "ShowInfoFindings", false } });

        Assert.False(actual);
    }

    [Fact]
    public void DesiredStateExportRequestUsesSharedExportDefaults()
    {
        var snapshot = CaptureExportDefaults();
        try
        {
            ExportDefaults.OutputDirectory = "reports";
            ExportDefaults.OpenInBrowser = true;
            ExportDefaults.NarrativePlacement = NarrativePlacement.Global;
            ExportDefaults.CompanyName = "Evotec";
            ExportDefaults.CompanyAddress = "Street";
            ExportDefaults.CompanyYear = "2026";
            ExportDefaults.LogoPath = "logo.png";
            ExportDefaults.HeaderText = "Header";
            ExportDefaults.FooterText = "Footer";
            ExportDefaults.WatermarkText = "Confidential";
            ExportDefaults.HeaderLogoSizePx = 64;
            ExportDefaults.FooterLogoSizePx = 32;

            var request = CmdletTestDesiredState.CreateExportRequest(
                new object[] { "view" },
                new[] { ReportFormat.Html },
                exportPath: null,
                openInBrowserRequested: false,
                defaultOpenInBrowser: ExportDefaults.OpenInBrowser);

            Assert.Equal("reports", request.DefaultOutputDirectory);
            Assert.True(request.OpenInBrowser);
            Assert.Equal(NarrativePlacement.Global, request.NarrativePlacement);
            Assert.Equal("Evotec", request.CompanyName);
            Assert.Equal("Street", request.CompanyAddress);
            Assert.Equal("2026", request.CompanyYear);
            Assert.Equal("logo.png", request.LogoPath);
            Assert.Equal("Header", request.HeaderText);
            Assert.Equal("Footer", request.FooterText);
            Assert.Equal("Confidential", request.WatermarkText);
            Assert.Equal(64, request.HeaderLogoSizePx);
            Assert.Equal(32, request.FooterLogoSizePx);
        }
        finally
        {
            RestoreExportDefaults(snapshot);
        }
    }

    private static ExportDefaultsSnapshot CaptureExportDefaults()
    {
        return new ExportDefaultsSnapshot
        {
            Format = ExportDefaults.Format,
            OpenInBrowser = ExportDefaults.OpenInBrowser,
            OutputDirectory = ExportDefaults.OutputDirectory,
            NarrativePlacement = ExportDefaults.NarrativePlacement,
            CompanyName = ExportDefaults.CompanyName,
            CompanyAddress = ExportDefaults.CompanyAddress,
            CompanyYear = ExportDefaults.CompanyYear,
            LogoPath = ExportDefaults.LogoPath,
            HeaderText = ExportDefaults.HeaderText,
            WatermarkText = ExportDefaults.WatermarkText,
            FooterText = ExportDefaults.FooterText,
            HeaderLogoSizePx = ExportDefaults.HeaderLogoSizePx,
            FooterLogoSizePx = ExportDefaults.FooterLogoSizePx
        };
    }

    private static void RestoreExportDefaults(ExportDefaultsSnapshot snapshot)
    {
        ExportDefaults.Format = snapshot.Format;
        ExportDefaults.OpenInBrowser = snapshot.OpenInBrowser;
        ExportDefaults.OutputDirectory = snapshot.OutputDirectory;
        ExportDefaults.NarrativePlacement = snapshot.NarrativePlacement;
        ExportDefaults.CompanyName = snapshot.CompanyName;
        ExportDefaults.CompanyAddress = snapshot.CompanyAddress;
        ExportDefaults.CompanyYear = snapshot.CompanyYear;
        ExportDefaults.LogoPath = snapshot.LogoPath;
        ExportDefaults.HeaderText = snapshot.HeaderText;
        ExportDefaults.WatermarkText = snapshot.WatermarkText;
        ExportDefaults.FooterText = snapshot.FooterText;
        ExportDefaults.HeaderLogoSizePx = snapshot.HeaderLogoSizePx;
        ExportDefaults.FooterLogoSizePx = snapshot.FooterLogoSizePx;
    }

    private sealed class ExportDefaultsSnapshot
    {
        public ReportFormat Format { get; set; }
        public bool OpenInBrowser { get; set; }
        public string OutputDirectory { get; set; } = string.Empty;
        public NarrativePlacement NarrativePlacement { get; set; }
        public string CompanyName { get; set; } = string.Empty;
        public string CompanyAddress { get; set; } = string.Empty;
        public string CompanyYear { get; set; } = string.Empty;
        public string LogoPath { get; set; } = string.Empty;
        public string HeaderText { get; set; } = string.Empty;
        public string WatermarkText { get; set; } = string.Empty;
        public string FooterText { get; set; } = string.Empty;
        public int? HeaderLogoSizePx { get; set; }
        public int? FooterLogoSizePx { get; set; }
    }
}
