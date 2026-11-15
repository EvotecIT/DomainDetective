using System;
using System.Collections.Generic;
using System.IO;
using DomainDetective.Reports.Markdown;
using Xunit;

namespace DomainDetective.Tests.Reports
{
    public class TestMailTlsParity
    {
        [Fact]
        public void Markdown_Includes_MailTls_Section_With_Service_Statuses()
        {
            var items = new List<object>();
            var domain = "example.org";
            items.Add(new DomainDetective.Views.MxInfo { Subject = domain, Status = "OK" });

            items.Add(new DomainDetective.Views.MailTlsInfo {
                Subject = domain,
                Check = DomainDetective.HealthCheckType.SMTPTLS,
                Status = "OK",
                Servers = new [] {
                    new DomainDetective.Views.MailTlsServerInfo { Key = "mx1.example.org:25", HostName = "mx1.example.org", Port = 25, Protocol = "TLS 1.3", StartTlsAdvertised = true, SupportsTls13 = true, Tls13Used = true, Grade = DomainDetective.GradeLevel.A, DaysToExpire = 90, CertificateValid = true, ChainValid = true }
                },
                Assessments = Array.Empty<DomainDetective.Assessment>(),
                References = Array.Empty<string>()
            });

            items.Add(new DomainDetective.Views.MailTlsInfo {
                Subject = domain,
                Check = DomainDetective.HealthCheckType.IMAPTLS,
                Status = "Warning",
                Servers = new [] {
                    new DomainDetective.Views.MailTlsServerInfo { Key = "imap.example.org:993", HostName = "imap.example.org", Port = 993, Protocol = "TLS 1.3", StartTlsAdvertised = true, SupportsTls13 = true, Tls13Used = true, Grade = DomainDetective.GradeLevel.B, DaysToExpire = 15, CertificateValid = true, ChainValid = true }
                },
                Assessments = Array.Empty<DomainDetective.Assessment>(),
                References = Array.Empty<string>()
            });

            items.Add(new DomainDetective.Views.MailTlsInfo {
                Subject = domain,
                Check = DomainDetective.HealthCheckType.POP3TLS,
                Status = "Error",
                Servers = new [] {
                    new DomainDetective.Views.MailTlsServerInfo { Key = "pop.example.org:995", HostName = "pop.example.org", Port = 995, StartTlsAdvertised = false, SupportsTls13 = false, Tls13Used = false, Grade = DomainDetective.GradeLevel.F, DaysToExpire = -1, CertificateValid = false, ChainValid = false }
                },
                Assessments = Array.Empty<DomainDetective.Assessment>(),
                References = Array.Empty<string>()
            });

            var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".md");
            var report = DomainDetective.Reports.DomainAssessmentBuilder.Build(items);
            var domainAssessment = Assert.Single(report.Domains);
            foreach (var expected in new[] { ("mx1.example.org", "25"), ("imap.example.org", "993"), ("pop.example.org", "995") }) {
                Assert.Contains(domainAssessment.Checks.SelectMany(check => check.Evidence).SelectMany(evidence => evidence.Rows),
                    row => row.Count >= 2 && row[0] == expected.Item1 && row[1] == expected.Item2);
            }
            AssessmentMarkdownReport.Generate(tmp, report);
            try {
                var text = ReportArtifactText.Read(tmp);
                Assert.Contains("mx1.example.org", text);
                Assert.Contains("imap.example.org", text);
                Assert.Contains("pop.example.org", text);
                Assert.Contains("SMTP", text, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("IMAP", text, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("POP3", text, StringComparison.OrdinalIgnoreCase);
            } finally { File.Delete(tmp); }
        }
    }
}
