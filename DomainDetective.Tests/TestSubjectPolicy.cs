using System;
using System.Collections.Generic;
using Xunit;
using DomainDetective;
using DomainDetective.Views;

namespace DomainDetective.Tests {
    public class TestSubjectPolicy {
        [Fact]
        public void PortScan_Subject_ComesFromAnalysis() {
            var analysis = new PortScanAnalysis {
                Subject = "example.com"
            };
            analysis.Results[80] = new PortScanAnalysis.ScanResult { TcpOpen = true, UdpOpen = false, TcpLatency = TimeSpan.FromMilliseconds(10) };
            var view = Converters.Convert(analysis);
            Assert.Equal("example.com", view.Subject);
        }

        [Fact]
        public void PortAvailability_SingleTarget_SetsSubject() {
            var analysis = new PortAvailabilityAnalysis();
            analysis.ServerResults["mail.example.com:25"] = new PortAvailabilityAnalysis.PortResult { Success = true, Latency = TimeSpan.FromMilliseconds(5) };
            var view = Converters.Convert(analysis);
            Assert.Equal("mail.example.com:25", view.Subject);
        }

        [Fact]
        public void PortAvailability_MultipleTargets_SubjectIsNull() {
            var analysis = new PortAvailabilityAnalysis();
            analysis.ServerResults["mx1.example.com:25"] = new PortAvailabilityAnalysis.PortResult { Success = true, Latency = TimeSpan.FromMilliseconds(5) };
            analysis.ServerResults["mx2.example.com:25"] = new PortAvailabilityAnalysis.PortResult { Success = false, Latency = TimeSpan.FromMilliseconds(5) };
            var view = Converters.Convert(analysis);
            Assert.Null(view.Subject);
        }

        [Fact]
        public void MailLatency_SingleTarget_SetsSubject() {
            var analysis = new MailLatencyAnalysis();
            analysis.ServerResults["mx.example.com:25"] = new MailLatencyAnalysis.LatencyResult {
                ConnectSuccess = true,
                BannerSuccess = true,
                ConnectTime = TimeSpan.FromMilliseconds(20),
                BannerTime = TimeSpan.FromMilliseconds(30)
            };
            var view = Converters.Convert(analysis);
            Assert.Equal("mx.example.com:25", view.Subject);
        }

        [Fact]
        public void MailLatency_MultipleTargets_SubjectIsNull() {
            var analysis = new MailLatencyAnalysis();
            analysis.ServerResults["mx1.example.com:25"] = new MailLatencyAnalysis.LatencyResult { ConnectSuccess = true, BannerSuccess = true, ConnectTime = TimeSpan.FromMilliseconds(10), BannerTime = TimeSpan.FromMilliseconds(15) };
            analysis.ServerResults["mx2.example.com:25"] = new MailLatencyAnalysis.LatencyResult { ConnectSuccess = false, BannerSuccess = false, ConnectTime = TimeSpan.FromMilliseconds(12), BannerTime = TimeSpan.Zero };
            var view = Converters.Convert(analysis);
            Assert.Null(view.Subject);
        }

        [Fact]
        public void DNSBL_DomainSubject_IsUsed() {
            var analysis = new DNSBLAnalysis { Subject = "example.com" };
            analysis.Results["example.com"] = new DNSQueryResult { Host = "example.com", DNSBLRecords = Array.Empty<DNSBLRecord>() };
            var view = Converters.Convert(analysis);
            Assert.Equal("example.com", view.Subject);
        }

        [Fact]
        public void DNSBL_NoSubject_RemainsNull() {
            var analysis = new DNSBLAnalysis();
            analysis.Results["1.2.3.4"] = new DNSQueryResult { Host = "1.2.3.4", DNSBLRecords = Array.Empty<DNSBLRecord>() };
            var view = Converters.Convert(analysis);
            Assert.Null(view.Subject);
        }
    }
}

