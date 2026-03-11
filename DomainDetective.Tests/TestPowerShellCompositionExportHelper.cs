using System;
using System.Collections.Generic;
using System.IO;
using DomainDetective;
using DomainDetective.PowerShell;
using DomainDetective.Reports;
using DomainDetective.Views;

namespace DomainDetective.Tests;

[Collection("ExportDefaults")]
public class TestPowerShellCompositionExportHelper
{
    [Fact]
    public void WriteReports_Generates_Word_And_Html_For_Requested_Formats()
    {
        var snapshot = ExportDefaultsSnapshot.Capture();
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"dd-export-helper-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDirectory);

        try
        {
            ExportDefaults.OutputDirectory = tempDirectory;
            ExportDefaults.OpenInBrowser = false;
            ExportDefaults.NarrativeTitle = string.Empty;
            ExportDefaults.NarrativeSubject = string.Empty;
            ExportDefaults.NarrativeCategory = string.Empty;
            ExportDefaults.NarrativeKeywords = string.Empty;
            ExportDefaults.NarrativeCreator = string.Empty;
            ExportDefaults.LogoPath = string.Empty;
            ExportDefaults.HeaderText = string.Empty;
            ExportDefaults.FooterText = string.Empty;
            ExportDefaults.WatermarkText = string.Empty;
            ExportDefaults.CompanyName = string.Empty;
            ExportDefaults.CompanyAddress = string.Empty;
            ExportDefaults.CompanyYear = string.Empty;

            var hadUnsupportedFormats = false;
            var generatedPaths = CompositionExportHelper.WriteReports(
                new List<object> { CreateSpfView() },
                new[] { ReportFormat.Word, ReportFormat.Html },
                explicitPath: null,
                label: "example.com",
                scope: ReportScope.Normal,
                defaultTitle: "Export Helper Test",
                openInBrowser: false,
                openReport: null,
                out hadUnsupportedFormats);

            Assert.False(hadUnsupportedFormats);
            Assert.Equal(2, generatedPaths.Count);
            Assert.Contains(generatedPaths, path => path.EndsWith(".docx", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(generatedPaths, path => path.EndsWith(".html", StringComparison.OrdinalIgnoreCase));
            Assert.All(generatedPaths, path => Assert.True(File.Exists(path), $"Expected export file to exist: {path}"));
        }
        finally
        {
            snapshot.Restore();
            try
            {
                if (Directory.Exists(tempDirectory))
                {
                    Directory.Delete(tempDirectory, recursive: true);
                }
            }
            catch
            {
            }
        }
    }

    [Fact]
    public void WriteReports_Continues_With_Supported_Formats_When_Unsupported_Format_Is_Requested()
    {
        var snapshot = ExportDefaultsSnapshot.Capture();
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"dd-export-helper-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDirectory);

        try
        {
            ExportDefaults.OutputDirectory = tempDirectory;
            ExportDefaults.OpenInBrowser = false;
            ExportDefaults.NarrativeTitle = string.Empty;
            ExportDefaults.NarrativeSubject = string.Empty;
            ExportDefaults.NarrativeCategory = string.Empty;
            ExportDefaults.NarrativeKeywords = string.Empty;
            ExportDefaults.NarrativeCreator = string.Empty;
            ExportDefaults.LogoPath = string.Empty;
            ExportDefaults.HeaderText = string.Empty;
            ExportDefaults.FooterText = string.Empty;
            ExportDefaults.WatermarkText = string.Empty;
            ExportDefaults.CompanyName = string.Empty;
            ExportDefaults.CompanyAddress = string.Empty;
            ExportDefaults.CompanyYear = string.Empty;

            var hadUnsupportedFormats = false;
            var generatedPaths = CompositionExportHelper.WriteReports(
                new List<object> { CreateSpfView() },
                new[] { ReportFormat.Html, ReportFormat.Pdf },
                explicitPath: null,
                label: "example.com",
                scope: ReportScope.Normal,
                defaultTitle: "Export Helper Test",
                openInBrowser: false,
                openReport: null,
                out hadUnsupportedFormats);

            Assert.True(hadUnsupportedFormats);
            Assert.Single(generatedPaths);
            Assert.EndsWith(".html", generatedPaths[0], StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(generatedPaths[0]));
        }
        finally
        {
            snapshot.Restore();
            try
            {
                if (Directory.Exists(tempDirectory))
                {
                    Directory.Delete(tempDirectory, recursive: true);
                }
            }
            catch
            {
            }
        }
    }

    private static SpfRecordInfo CreateSpfView()
    {
        return new SpfRecordInfo
        {
            Check = HealthCheckType.SPF,
            Area = AnalysisArea.Mail,
            Subject = "example.com",
            SpfRecord = "v=spf1 -all",
            Assessments = Array.Empty<Assessment>(),
            Recommendations = Array.Empty<RecommendationAdvice>(),
            Positives = Array.Empty<RecommendationAdvice>()
        };
    }

    private sealed class ExportDefaultsSnapshot
    {
        private readonly ReportFormat _format;
        private readonly bool _openInBrowser;
        private readonly string _outputDirectory;
        private readonly bool _emitArtifacts;
        private readonly string _artifactsDirectory;
        private readonly NarrativePlacement _narrativePlacement;
        private readonly string _narrativeTitle;
        private readonly string _narrativeSubject;
        private readonly string _narrativeCategory;
        private readonly string _narrativeKeywords;
        private readonly string _narrativeCreator;
        private readonly string _logoPath;
        private readonly int? _headerLogoSizePx;
        private readonly int? _footerLogoSizePx;
        private readonly string _headerText;
        private readonly string _footerText;
        private readonly string _watermarkText;
        private readonly int _summaryColumnCap;
        private readonly string _companyName;
        private readonly string _companyAddress;
        private readonly string _companyYear;

        private ExportDefaultsSnapshot()
        {
            _format = ExportDefaults.Format;
            _openInBrowser = ExportDefaults.OpenInBrowser;
            _outputDirectory = ExportDefaults.OutputDirectory;
            _emitArtifacts = ExportDefaults.EmitArtifacts;
            _artifactsDirectory = ExportDefaults.ArtifactsDirectory;
            _narrativePlacement = ExportDefaults.NarrativePlacement;
            _narrativeTitle = ExportDefaults.NarrativeTitle;
            _narrativeSubject = ExportDefaults.NarrativeSubject;
            _narrativeCategory = ExportDefaults.NarrativeCategory;
            _narrativeKeywords = ExportDefaults.NarrativeKeywords;
            _narrativeCreator = ExportDefaults.NarrativeCreator;
            _logoPath = ExportDefaults.LogoPath;
            _headerLogoSizePx = ExportDefaults.HeaderLogoSizePx;
            _footerLogoSizePx = ExportDefaults.FooterLogoSizePx;
            _headerText = ExportDefaults.HeaderText;
            _footerText = ExportDefaults.FooterText;
            _watermarkText = ExportDefaults.WatermarkText;
            _summaryColumnCap = ExportDefaults.SummaryColumnCap;
            _companyName = ExportDefaults.CompanyName;
            _companyAddress = ExportDefaults.CompanyAddress;
            _companyYear = ExportDefaults.CompanyYear;
        }

        internal static ExportDefaultsSnapshot Capture()
        {
            return new ExportDefaultsSnapshot();
        }

        internal void Restore()
        {
            ExportDefaults.Format = _format;
            ExportDefaults.OpenInBrowser = _openInBrowser;
            ExportDefaults.OutputDirectory = _outputDirectory;
            ExportDefaults.EmitArtifacts = _emitArtifacts;
            ExportDefaults.ArtifactsDirectory = _artifactsDirectory;
            ExportDefaults.NarrativePlacement = _narrativePlacement;
            ExportDefaults.NarrativeTitle = _narrativeTitle;
            ExportDefaults.NarrativeSubject = _narrativeSubject;
            ExportDefaults.NarrativeCategory = _narrativeCategory;
            ExportDefaults.NarrativeKeywords = _narrativeKeywords;
            ExportDefaults.NarrativeCreator = _narrativeCreator;
            ExportDefaults.LogoPath = _logoPath;
            ExportDefaults.HeaderLogoSizePx = _headerLogoSizePx;
            ExportDefaults.FooterLogoSizePx = _footerLogoSizePx;
            ExportDefaults.HeaderText = _headerText;
            ExportDefaults.FooterText = _footerText;
            ExportDefaults.WatermarkText = _watermarkText;
            ExportDefaults.SummaryColumnCap = _summaryColumnCap;
            ExportDefaults.CompanyName = _companyName;
            ExportDefaults.CompanyAddress = _companyAddress;
            ExportDefaults.CompanyYear = _companyYear;
        }
    }
}
