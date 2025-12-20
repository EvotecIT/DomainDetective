using System;
using System.Linq;
using DnsClientX;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Verifies MTA-STS policy for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyMTASTS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            MTASTSAnalysis = new MTASTSAnalysis {
                PolicyUrlOverride = MtaStsPolicyUrlOverride,
                DnsConfiguration = DnsConfiguration
            };
            // Analyze policy (TXT + HTTPS fetch + syntax)
            await MTASTSAnalysis.AnalyzePolicy(domainName, _logger);

            // Correlate with MX TLS posture: ensure MX advertise STARTTLS and negotiate modern TLS
            try {
                var hosts = await GetMxHostsAsync(domainName, cancellationToken);
                // If we don't already have SMTP TLS results for these hosts: run SMTPTLS probe
                bool haveCoverage = hosts.Length > 0 && hosts.All(h => SmtpTlsAnalysis.ServerResults.ContainsKey($"{h}:25"));
                if (!haveCoverage && hosts.Length > 0) {
                    await EnsureSmtpTlsAsync(domainName, 25, cancellationToken);
                }
                if (hosts.Length > 0 && SmtpTlsAnalysis?.ServerResults != null && SmtpTlsAnalysis.ServerResults.Count > 0) {
                    bool allModern = true;
                    foreach (var h in hosts) {
                        var key = $"{h}:25";
                        if (!SmtpTlsAnalysis.ServerResults.TryGetValue(key, out var r) || r == null) {
                            allModern = false; // missing data -> treat as not modern
                            MTASTSAnalysis.Assessments.Add(new Assessment {
                                Severity = AssessmentSeverity.Warning,
                                Category = "MTASTS",
                                Code = MtaStsCodes.MxStartTlsMissing,
                                Target = h,
                                Message = "No TLS data collected for MX host (STARTTLS may be missing)."
                            });
                            continue;
                        }

                        if (!r.StartTlsAdvertised) {
                            allModern = false;
                            MTASTSAnalysis.Assessments.Add(new Assessment {
                                Severity = AssessmentSeverity.Warning,
                                Category = "MTASTS",
                                Code = MtaStsCodes.MxStartTlsMissing,
                                Target = h,
                                Message = "MX host does not advertise STARTTLS."
                            });
                            continue;
                        }

                        // Acceptable when TLS 1.2 or 1.3 negotiated and grade >= B
                        bool modernProto = r.Tls13Used || r.Protocol == System.Security.Authentication.SslProtocols.Tls12;
                        bool modernGrade = !r.LegacyEnabled && r.GradeLevel.IsAtLeast(GradeLevel.B);
                        if (!(modernProto && modernGrade)) {
                            allModern = false;
                            MTASTSAnalysis.Assessments.Add(new Assessment {
                                Severity = AssessmentSeverity.Warning,
                                Category = "MTASTS",
                                Code = MtaStsCodes.MxTlsWeak,
                                Target = h,
                                Message = "MX host negotiates legacy/weak TLS (require TLS 1.2+ and modern ciphers)."
                            });
                        }
                    }

                    if (allModern) {
                        MTASTSAnalysis.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Info,
                            Category = "MTASTS",
                            Code = MtaStsCodes.MxTlsModernAll,
                            Target = domainName,
                            Message = "All MX hosts advertise STARTTLS and negotiate modern TLS (TLS 1.2/1.3)."
                        });
                    }
                }
            } catch (Exception ex) {
                _logger?.WriteVerbose($"MTA-STS TLS correlation skipped: {ex.Message}");
            }
        }
    }
}
