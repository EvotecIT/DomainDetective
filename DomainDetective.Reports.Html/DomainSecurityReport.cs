using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using DomainDetective.Reports.Models;
using DomainDetective.Reports.Enums;
using DomainDetective.Reports.Html.Models;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Proof of concept for DomainDetective HTML report generation using HtmlForgeX
/// </summary>
public class DomainSecurityReport {
    private readonly DomainHealthCheck _healthCheck;
    private readonly SecurityScore _score;
    private readonly string _domain;

    public DomainSecurityReport(DomainHealthCheck healthCheck, string domain) {
        _healthCheck = healthCheck;
        _domain = domain;
        _score = CalculateSecurityScore();
    }

    public void GenerateReport(string outputPath, bool openInBrowser = true) {
        using var document = new Document {
            Head = {
                Title = $"Security Report - {_domain}",
                Author = "DomainDetective",
                Revised = DateTime.Now,
                Description = $"Comprehensive security analysis for {_domain}"
            },
            LibraryMode = LibraryMode.Online,
            ThemeMode = ThemeMode.Light
        };

        document.Body.Page(page => {
            page.Layout = TablerLayout.Fluid;
            
            // Header
            CreateHeader(page);
            
            // Score Dashboard
            CreateScoreDashboard(page);
            
            // Category Analysis
            CreateCategoryAnalysis(page);
            
            // Detailed Results
            CreateDetailedResults(page);
            
            // Recommendations
            CreateRecommendations(page);

            // Facts (Info-level signals)
            CreateFacts(page);

            // Technical Details
            CreateTechnicalDetails(page);
        });

        document.Save(outputPath, openInBrowser);
    }

    private void CreateFacts(TablerPage page) {
        try {
            var infos = _healthCheck.GetAllAssessments()?.Where(a => a.Severity == AssessmentSeverity.Info).ToList() ?? new List<Assessment>();
            if (infos.Count == 0) return;
            page.Divider("Facts & Signals");
            page.Row(row => {
                row.Column(TablerColumnNumber.Twelve, col => {
                    col.Card(card => {
                        card.Header(h => h.Title("Informational Signals"));
                        card.Body(body => {
                            var table = (TablerTable)body.Table(infos.Select(i => new {
                                Category = i.Category,
                                Code = i.Code ?? string.Empty,
                                Target = i.Target ?? string.Empty,
                                Message = i.Message
                            }), TableType.Tabler);
                            table.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        });
                    });
                });
            });
        } catch { }
    }

    private void CreateHeader(TablerPage page) {
        page.Row(row => {
            row.Column(TablerColumnNumber.Twelve, col => {
                col.H1($"🛡️ Security Report for {_domain}");
                col.Text($"Generated on {DateTime.Now:yyyy-MM-dd HH:mm:ss}")
                   .Style(TablerTextStyle.Muted);
            });
        });
    }

    private void CreateScoreDashboard(TablerPage page) {
        page.Divider("Security Score Overview");
        
        page.Row(row => {
            // Main Score Gauge
            row.Column(TablerColumnNumber.Four, col => {
                col.Card(card => {
                    card.Background(GetScoreBackgroundColor(_score.OverallScore), "#FFFFFF")
                        .Header(header => {
                            header.Title("Overall Security Score")
                                  .Subtitle(GetRiskLevelText(_score.RiskLevel));
                        })
                        .Body(body => {
                            // Score display
                            body.H1($"{_score.OverallScore}");
                            body.Text("out of 100").Style(TablerTextStyle.Muted).Weight(TablerFontWeight.Medium);
                        });
                });
            });
            
            // Category Cards
            row.Column(TablerColumnNumber.Eight, col => {
                col.Row(catRow => {
                    CreateCategoryCard(catRow, _score.Impersonation, "🛡️", "#8B5CF6");
                    CreateCategoryCard(catRow, _score.Privacy, "🔒", "#3B82F6");
                    CreateCategoryCard(catRow, _score.Branding, "🏆", "#10B981");
                    CreateCategoryCard(catRow, _score.Infrastructure, "🖥️", "#F59E0B");
                });
            });
        });
        
        // Quick Stats
        page.Row(row => {
            CreateQuickStat(row, "Total Checks", GetTotalChecks(), TablerColor.Blue);
            CreateQuickStat(row, "Passed", GetPassedChecks(), TablerColor.Success);
            CreateQuickStat(row, "Warnings", GetWarningChecks(), TablerColor.Warning);
            CreateQuickStat(row, "Failed", GetFailedChecks(), TablerColor.Danger);
        });
    }

    private void CreateCategoryCard(TablerRow row, SecurityCategory category, string icon, string color) {
        row.Column(TablerColumnNumber.Three, col => {
            col.Card(card => {
                card.Background(color, "#FFFFFF")
                    .Header(header => {
                        header.Title($"{icon} {category.Name}")
                              .Avatar(avatar => {
                                  avatar.BackgroundColor(color, "#FFFFFF")
                                        .Text(icon);
                              });
                    })
                    .Body(body => {
                        body.H2($"{category.Score}/{category.MaxScore}");
                        body.Text(GetRiskText(category.Risk)).Weight(TablerFontWeight.Medium);
                        
                        // Progress will be added outside body
                    });
                
                // Progress bar
                var percentage = (int)(category.Score * 100.0 / category.MaxScore);
                card.Progress(percentage, GetTablerColor(category.Risk));
            });
        });
    }

    private void CreateQuickStat(TablerRow row, string label, int value, TablerColor color) {
        row.Column(TablerColumnNumber.Three, col => {
            col.Card(card => {
                card.Body(body => {
                    body.DataGrid(grid => {
                        grid.AsCompact()
                            .AddItem(label, value.ToString());
                    });
                });
            });
        });
    }

    private void CreateCategoryAnalysis(TablerPage page) {
        page.Divider("Category Analysis");
        
        page.Row(row => {
            row.Column(TablerColumnNumber.Twelve, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Security Categories Breakdown"));
                    card.Body(body => {
                        body.DataGrid(grid => {
                            grid.AddItem("Impersonation", $"{_score.Impersonation.Score}/{_score.Impersonation.MaxScore}");
                            grid.AddItem("Privacy", $"{_score.Privacy.Score}/{_score.Privacy.MaxScore}");
                            grid.AddItem("Branding", $"{_score.Branding.Score}/{_score.Branding.MaxScore}");
                            grid.AddItem("Infrastructure", $"{_score.Infrastructure.Score}/{_score.Infrastructure.MaxScore}");
                        });
                    });
                });
            });
        });
    }

    private void CreateDetailedResults(TablerPage page) {
        page.Divider("Detailed Security Checks");
        
        var checkResults = GetAllCheckResults();
        
        // Create a table manually for now
        page.Row(row => {
            row.Column(TablerColumnNumber.Twelve, col => {
                col.Card(card => {
                    card.Body(body => {
                        // Create table using HtmlForgeX table API
                        if (checkResults.Any()) {
                            var table = (TablerTable)body.Table(checkResults, TableType.Tabler);
                            table.Style(BootStrapTableStyle.Striped)
                                 .Style(BootStrapTableStyle.Hover);
                        }
                    });
                });
            });
        });
    }

    private void CreateRecommendations(TablerPage page) {
        page.Divider("Priority Recommendations");
        
        page.Row(row => {
            foreach (var rec in _score.Recommendations.Take(3)) {
                row.Column(TablerColumnNumber.Four, col => {
                    col.Card(card => {
                        card.Ribbon(GetPriorityText(rec.Priority), GetPriorityColor(rec.Priority))
                            .Header(header => {
                                header.Title(rec.Title);
                            })
                            .Body(body => {
                                body.Text(rec.Description);
                                body.Divider();
                                
                                body.H5("Implementation Steps:");
                                body.AddList(list => {
                                    list.WithItems(items => {
                                        foreach (var step in rec.Steps) {
                                            items.Item(step);
                                        }
                                    });
                                });
                                
                                body.DataGrid(grid => {
                                    grid.AsCompact();
                                    grid.AddItem("Effort", rec.Effort.ToString());
                                    grid.AddItem("Score Impact", $"+{rec.PotentialScoreIncrease}");
                                });
                            });
                    });
                });
            }
        });
    }

    private void CreateTechnicalDetails(TablerPage page) {
        page.Divider("Technical Details");
        
        page.Row(row => {
            // SPF/DMARC/DKIM Details
            row.Column(TablerColumnNumber.Six, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Email Authentication"));
                    card.Body(body => {
                        body.DataGrid(grid => {
                            grid.AddItem("SPF Record", _healthCheck.SpfAnalysis?.SpfRecordExists == true ? "Found" : "Not found");
                            grid.AddItem("SPF Valid",
                                _healthCheck.SpfAnalysis?.StartsCorrectly == true ? "Yes" : "No");

                            grid.AddItem("DMARC Policy", _healthCheck.DmarcAnalysis?.Policy ?? "Not found");
                            grid.AddItem("DMARC Valid",
                                _healthCheck.DmarcAnalysis?.DmarcRecordExists == true ? "Yes" : "No");

                            grid.AddItem("DKIM Valid",
                                _healthCheck.DKIMAnalysis?.AnalysisResults?.Count > 0 ? "Yes" : "No");
                        });

                        if (_healthCheck.SpfAnalysis?.SpfRecordExists == true) {
                            var tree = _healthCheck.SpfAnalysis.GetFlattenedSpfTree().GetAwaiter().GetResult();
                            body.DataGrid(tg => {
                                tg.AddItem("Flattened SPF", string.Join("\n", tree));
                                foreach (var warn in _healthCheck.SpfAnalysis.Warnings) {
                                    tg.AddItem("Warning", warn);
                                }
                            });
                        }
                    });
                });
            });
            
            // DNS Security
            row.Column(TablerColumnNumber.Six, col => {
                col.Card(card => {
                    card.Header(h => h.Title("DNS Security"));
                    card.Body(body => {
                        body.DataGrid(grid => {
                            grid.AddItem("DNSSEC",
                                _healthCheck.DnsSecAnalysis?.DsRecords?.Count > 0 ? "Enabled" : "Disabled");
                            
                            grid.AddItem("Name Servers", 
                                _healthCheck.NSAnalysis?.NsRecordExists == true ? "Found" : "Not found");
                            
                            grid.AddItem("MX Records",
                                _healthCheck.MXAnalysis?.MxRecordExists == true ? "Found" : "Not found");
                        });
                    });
                });
            });
        });
    }

    // Helper methods
    private SecurityScore CalculateSecurityScore() {
        // This is a simplified scoring algorithm - expand based on requirements
        var score = new SecurityScore {
            Impersonation = CalculateCategoryScore("Impersonation", 
                _healthCheck.SpfAnalysis, _healthCheck.DmarcAnalysis, _healthCheck.DKIMAnalysis),
            Privacy = CalculateCategoryScore("Privacy",
                _healthCheck.SmtpTlsAnalysis, _healthCheck.DaneAnalysis),
            Branding = CalculateCategoryScore("Branding",
                _healthCheck.BimiAnalysis),
            Infrastructure = CalculateCategoryScore("Infrastructure",
                _healthCheck.DnsSecAnalysis, _healthCheck.NSAnalysis, _healthCheck.MXAnalysis)
        };
        
        // Calculate overall score
        var totalScore = (score.Impersonation.Score + score.Privacy.Score + 
                         score.Branding.Score + score.Infrastructure.Score) * 5;
        
        score.OverallScore = Math.Min(100, totalScore);
        score.RiskLevel = GetRiskLevel(score.OverallScore);
        
        // Add recommendations
        score.Recommendations = GenerateRecommendations();
        
        return score;
    }

    private SecurityCategory CalculateCategoryScore(string name, params object[] analyses) {
        var validCount = analyses.Count(a => IsAnalysisValid(a));
        var score = validCount * 5 / analyses.Length;
        
        return new SecurityCategory {
            Name = name,
            Score = score,
            MaxScore = 5,
            Risk = score >= 4 ? SecurityRiskLevel.Low : 
                   score >= 2 ? SecurityRiskLevel.Medium : SecurityRiskLevel.High
        };
    }

    private bool IsAnalysisValid(object analysis) {
        if (analysis == null) return false;
        
        var type = analysis.GetType();
        
        // Check specific analysis types
        if (type.Name == "SpfAnalysis") {
            return type.GetProperty("SpfRecordExists")?.GetValue(analysis) as bool? == true;
        }
        if (type.Name == "DmarcAnalysis") {
            return type.GetProperty("DmarcRecordExists")?.GetValue(analysis) as bool? == true;
        }
        if (type.Name == "DnsSecAnalysis") {
            var dsRecords = type.GetProperty("DsRecords")?.GetValue(analysis) as System.Collections.IList;
            return dsRecords?.Count > 0;
        }
        if (type.Name == "MXAnalysis") {
            return type.GetProperty("MxRecordExists")?.GetValue(analysis) as bool? == true;
        }
        if (type.Name == "NSAnalysis") {
            return type.GetProperty("NsRecordExists")?.GetValue(analysis) as bool? == true;
        }
        if (type.Name == "SMTPTLSAnalysis") {
            var serverResults = type.GetProperty("ServerResults")?.GetValue(analysis) as System.Collections.IDictionary;
            if (serverResults != null && serverResults.Count > 0) {
                foreach (var value in serverResults.Values) {
                    var resultType = value.GetType();
                    var certValid = resultType.GetProperty("CertificateValid")?.GetValue(value) as bool?;
                    if (certValid == true) return true;
                }
            }
            return false;
        }
        
        // Default check for other types
        var validProperty = type.GetProperty("Valid");
        if (validProperty != null) {
            return validProperty.GetValue(analysis) as bool? == true;
        }
        
        return false;
    }

    private List<CheckResultRow> GetAllCheckResults() {
        var results = new List<CheckResultRow>();
        
        // Add all check results - this is simplified
        if (_healthCheck.SpfAnalysis != null) {
            results.Add(new CheckResultRow {
                Category = "Impersonation",
                Check = "SPF Record",
                Status = _healthCheck.SpfAnalysis.SpfRecordExists && _healthCheck.SpfAnalysis.StartsCorrectly ? "✅ Pass" : "❌ Fail",
                Points = _healthCheck.SpfAnalysis.SpfRecordExists && _healthCheck.SpfAnalysis.StartsCorrectly ? "10/10" : "0/10",
                Details = _healthCheck.SpfAnalysis.SpfRecordExists ? "SPF record found" : "No SPF record found"
            });
        }
        
        // Add more checks...
        
        return results;
    }

    private List<SecurityRecommendation> GenerateRecommendations() {
        var recommendations = new List<SecurityRecommendation>();
        
        if (!_healthCheck.DmarcAnalysis?.DmarcRecordExists ?? true) {
            recommendations.Add(new SecurityRecommendation {
                Priority = RecommendationPriority.Urgent,
                Title = "Implement DMARC Policy",
                Description = "DMARC protects against email spoofing and phishing attacks.",
                Steps = new List<string> {
                    "Create a DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + _domain,
                    "Start with p=none for monitoring",
                    "Gradually move to p=quarantine, then p=reject"
                },
                Effort = EffortLevel.Medium,
                PotentialScoreIncrease = 15
            });
        }
        
        return recommendations.OrderByDescending(r => r.Priority).ToList();
    }

    // Color and styling helpers
    private string GetScoreColor(int score) {
        return score >= 80 ? "#10B981" :
               score >= 60 ? "#F59E0B" :
               score >= 40 ? "#F97316" : "#EF4444";
    }

    private string GetScoreBackgroundColor(int score) {
        return score >= 80 ? "#10B981" :
               score >= 60 ? "#F59E0B" :
               score >= 40 ? "#F97316" : "#EF4444";
    }

    private SecurityRiskLevel GetRiskLevel(int score) {
        return score >= 80 ? SecurityRiskLevel.Low :
               score >= 60 ? SecurityRiskLevel.Medium :
               score >= 40 ? SecurityRiskLevel.High : SecurityRiskLevel.Critical;
    }

    private string GetRiskLevelText(SecurityRiskLevel risk) {
        return risk switch {
            SecurityRiskLevel.Low => "Low Risk",
            SecurityRiskLevel.Medium => "Medium Risk",
            SecurityRiskLevel.High => "High Risk",
            SecurityRiskLevel.Critical => "Critical Risk",
            _ => "Unknown"
        };
    }

    private string GetRiskText(SecurityRiskLevel risk) {
        return risk switch {
            SecurityRiskLevel.Low => "✓ Low Risk",
            SecurityRiskLevel.Medium => "⚠ Medium Risk",
            SecurityRiskLevel.High => "⚠ High Risk",
            SecurityRiskLevel.Critical => "✗ Critical Risk",
            _ => "Unknown"
        };
    }

    private string GetRiskColorClass(SecurityRiskLevel risk) {
        return risk switch {
            SecurityRiskLevel.Low => "success",
            SecurityRiskLevel.Medium => "warning",
            SecurityRiskLevel.High => "orange",
            SecurityRiskLevel.Critical => "danger",
            _ => "secondary"
        };
    }

    private string GetPriorityText(RecommendationPriority priority) {
        return priority.ToString().ToUpper();
    }

    private TablerColor GetPriorityColor(RecommendationPriority priority) {
        return priority switch {
            RecommendationPriority.Urgent => TablerColor.Red,
            RecommendationPriority.High => TablerColor.Orange,
            RecommendationPriority.Medium => TablerColor.Yellow,
            RecommendationPriority.Low => TablerColor.Blue,
            _ => TablerColor.Blue
        };
    }

    private int GetTotalChecks() => 25; // Placeholder
    private int GetPassedChecks() => 15; // Placeholder
    private int GetWarningChecks() => 5; // Placeholder
    private int GetFailedChecks() => 5; // Placeholder
    
    private TablerColor GetTablerColor(SecurityRiskLevel risk) {
        return risk switch {
            SecurityRiskLevel.Low => TablerColor.Success,
            SecurityRiskLevel.Medium => TablerColor.Warning,
            SecurityRiskLevel.High => TablerColor.Orange,
            SecurityRiskLevel.Critical => TablerColor.Danger,
            _ => TablerColor.Blue
        };
    }
}
