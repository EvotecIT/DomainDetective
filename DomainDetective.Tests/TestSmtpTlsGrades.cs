using DomainDetective;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestSmtpTlsGrades
{
    [Fact]
    public void SmtpTls_GradesSummaryCounts()
    {
        var tls = new SMTPTLSAnalysis { Subject = "example.com" };
        tls.ServerResults["mx-a.example.com:25"] = new MailTlsAnalysis.TlsResult { CertificateValid = true, GradeLevel = GradeLevel.A };
        tls.ServerResults["mx-b1.example.com:25"] = new MailTlsAnalysis.TlsResult { CertificateValid = true, GradeLevel = GradeLevel.B };
        tls.ServerResults["mx-b2.example.com:25"] = new MailTlsAnalysis.TlsResult { CertificateValid = false, GradeLevel = GradeLevel.B };
        tls.ServerResults["mx-d.example.com:25"] = new MailTlsAnalysis.TlsResult { CertificateValid = false, GradeLevel = GradeLevel.D };
        tls.ServerResults["mx-f.example.com:25"] = new MailTlsAnalysis.TlsResult { CertificateValid = false, GradeLevel = GradeLevel.F };

        var view = Converters.Convert(tls);
        Assert.Equal(5, view.Servers.Count);
        Assert.Contains("servers 5; valid cert 2/5; grades A/B/C/D/F: 1/2/0/1/1", view.Summary);
    }
}

