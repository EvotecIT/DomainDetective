using System.Collections.Generic;
using System.Security.Authentication;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestWebsiteNarrative
    {
        [Fact]
        public void BuildsCompositeNarrative()
        {
            var http = new HttpAnalysis { Subject = "example.com" };
            typeof(HttpAnalysis).GetProperty("StatusCode")!.SetValue(http, 200);
            http.SecurityHeaders["Strict-Transport-Security"] = new SecurityHeader("Strict-Transport-Security", "max-age=31536000");
            http.SecurityHeaders["Content-Security-Policy"] = new SecurityHeader("Content-Security-Policy", "default-src 'self'");
            typeof(HttpAnalysis).GetProperty("HstsPresent")!.SetValue(http, true);
            http.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = HttpCodes.HstsPresent, Message = "hsts" });
            http.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = HttpCodes.CspPresent, Message = "csp" });

            using var tls = new TlsAnalysis { Subject = "example.com" };
            tls.ServerResults["www.example.com:443"] = new TlsProbe.Result
            {
#if NET8_0_OR_GREATER
                Protocol = SslProtocols.Tls13,
#else
                Protocol = SslProtocols.Tls12,
#endif
                CipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                CertificateValid = true,
                HostnameMatch = true
            };
            tls.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = TlsCodes.StrongProtocol, Message = "tls" });

            var sections = WebsiteNarrative.Build(http, tls);
            Assert.Contains(sections.Highlights, h => h.Contains("HTTP"));
            Assert.Contains(sections.Highlights, h => h.Contains("TLS"));
            Assert.NotEmpty(sections.Positives);
        }

        [Fact]
        public void ProvidesPositiveAdvice()
        {
            var assessments = new List<Assessment>
            {
                new() { Severity = AssessmentSeverity.Info, Code = HttpCodes.HstsPresent, Message = "hsts" },
                new() { Severity = AssessmentSeverity.Info, Code = HttpCodes.CspPresent, Message = "csp" },
                new() { Severity = AssessmentSeverity.Info, Code = TlsCodes.StrongProtocol, Message = "tls" }
            };
            var positives = RecommendationEngine.FromPositives(assessments);
            Assert.Contains(positives, p => p.Code == HttpCodes.HstsPresent);
            Assert.Contains(positives, p => p.Code == HttpCodes.CspPresent);
            Assert.Contains(positives, p => p.Code == TlsCodes.StrongProtocol);
        }
    }
}

