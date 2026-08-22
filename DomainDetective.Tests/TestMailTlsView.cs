using System;
using DomainDetective;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestMailTlsView
{
    [Fact]
    public void IncludesCertificateSummaryFields()
    {
        var tls = new SMTPTLSAnalysis { Subject = "example.com" };
        var when = new DateTime(2025, 9, 1, 0, 0, 0, DateTimeKind.Utc);
        var until = new DateTime(2025, 12, 31, 0, 0, 0, DateTimeKind.Utc);
        tls.ServerResults["smtp.example.com:25"] = new MailTlsAnalysis.TlsResult
        {
            Connection = new MailTransportConnectionEvidence {
                HostName = "smtp.example.com",
                Port = 25,
                ConnectAddress = "192.0.2.10",
                RequestedAddressFamily = MailTransportAddressFamily.IPv4,
                RemoteAddress = "192.0.2.10",
                RemoteAddressFamily = MailTransportAddressFamily.IPv4
            },
            StartTlsAdvertised = true,
            CertificateValid = true,
            HostnameMatch = true,
            CertificateSubject = "CN=mail.example.com",
            CertificateIssuer = "Let's Encrypt",
            CertificateNotBefore = when,
            CertificateNotAfter = until,
            CertificateThumbprint = "ABCDEF123456"
        };

        var view = Converters.Convert(tls);
        var server = Assert.Single(view.Servers);
        Assert.Equal("Let's Encrypt", server.Issuer);
        Assert.Equal(when, server.ValidFrom);
        Assert.Equal(until, server.ValidTo);
        Assert.Equal("ABCDEF123456", server.Thumbprint);
        Assert.Equal("smtp.example.com", server.HostName);
        Assert.Equal(25, server.Port);
        Assert.Equal("192.0.2.10", server.ConnectAddress);
        Assert.Equal("192.0.2.10", server.RemoteAddress);
        Assert.Equal(MailTransportAddressFamily.IPv4, server.RequestedAddressFamily);
        Assert.Equal(MailTransportAddressFamily.IPv4, server.RemoteAddressFamily);
    }

    [Fact]
    public void IncludesCertificateFields_ForImapAndPop3()
    {
        var when = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var until = new DateTime(2025, 6, 30, 0, 0, 0, DateTimeKind.Utc);

        // IMAP
        var imap = new IMAPTLSAnalysis { Subject = "example.com" };
        imap.ServerResults["imap.example.com:143"] = new MailTlsAnalysis.TlsResult
        {
            StartTlsAdvertised = true,
            CertificateValid = true,
            CertificateIssuer = "Issuer-IMAP",
            CertificateNotBefore = when,
            CertificateNotAfter = until,
            CertificateThumbprint = "TH-IMAP"
        };
        var imapView = Converters.Convert(imap);
        var imapServer = Assert.Single(imapView.Servers);
        Assert.Equal("Issuer-IMAP", imapServer.Issuer);
        Assert.Equal(when, imapServer.ValidFrom);
        Assert.Equal(until, imapServer.ValidTo);
        Assert.Equal("TH-IMAP", imapServer.Thumbprint);

        // POP3
        var pop = new POP3TLSAnalysis { Subject = "example.com" };
        pop.ServerResults["pop.example.com:110"] = new MailTlsAnalysis.TlsResult
        {
            StartTlsAdvertised = true,
            CertificateValid = true,
            CertificateIssuer = "Issuer-POP",
            CertificateNotBefore = when,
            CertificateNotAfter = until,
            CertificateThumbprint = "TH-POP"
        };
        var popView = Converters.Convert(pop);
        var popServer = Assert.Single(popView.Servers);
        Assert.Equal("Issuer-POP", popServer.Issuer);
        Assert.Equal(when, popServer.ValidFrom);
        Assert.Equal(until, popServer.ValidTo);
        Assert.Equal("TH-POP", popServer.Thumbprint);
    }
}
