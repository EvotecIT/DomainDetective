using DnsClientX;
using DomainDetective;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestTLSRPTAnalysis {
        [Fact]
        public async Task ParseValidTlsRptPolicy() {
            var record = "v=TLSRPTv1;rua=mailto:reports@example.com";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckTLSRPT(record);
            Assert.True(healthCheck.TLSRPTAnalysis.PolicyValid);
            Assert.Single(healthCheck.TLSRPTAnalysis.MailtoRua);
            Assert.Equal("reports@example.com", healthCheck.TLSRPTAnalysis.MailtoRua[0]);
        }

        [Fact]
        public async Task MissingRuaInvalidatesPolicy() {
            var record = "v=TLSRPTv1";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckTLSRPT(record);
            Assert.False(healthCheck.TLSRPTAnalysis.RuaDefined);
            Assert.False(healthCheck.TLSRPTAnalysis.PolicyValid);
        }

        [Fact]
        public async Task SkipCnameRecordBeforeParsing() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = "alias.example.com",
                    Type = DnsRecordType.CNAME
                },
                new DnsAnswer {
                    DataRaw = "v=TLSRPTv1;rua=mailto:reports@example.com",
                    Type = DnsRecordType.TXT
                }
            };

            var analysis = new TLSRPTAnalysis();
            await analysis.AnalyzeTlsRptRecords(answers, new InternalLogger());

            Assert.True(analysis.PolicyValid);
        }

        [Fact]
        public async Task MissingRuaInvalidatesPolicyAnalysis() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "v=TLSRPTv1", Type = DnsRecordType.TXT }
            };
            var analysis = new TLSRPTAnalysis();
            await analysis.AnalyzeTlsRptRecords(answers, new InternalLogger());

            Assert.False(analysis.RuaDefined);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public async Task InvalidSchemeRecorded() {
            var record = "v=TLSRPTv1;rua=ftp://reports.example.com";
            var analysis = new TLSRPTAnalysis();
            await analysis.AnalyzeTlsRptRecords(new[] { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } }, new InternalLogger());

            Assert.Single(analysis.InvalidRua);
            Assert.Equal("ftp://reports.example.com", analysis.InvalidRua[0]);
        }

        [Fact]
        public async Task UnknownTagsAreCollected() {
            var record = "v=TLSRPTv1;rua=mailto:a@example.com;foo=bar;test";
            var analysis = new TLSRPTAnalysis();
            await analysis.AnalyzeTlsRptRecords(new[] { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } }, new InternalLogger());

            Assert.Contains("foo=bar", analysis.UnknownTags);
            Assert.Contains("test", analysis.UnknownTags);
            Assert.True(analysis.PolicyValid);
        }

        [Fact]
        public async Task DetectMultipleRecords() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "v=TLSRPTv1;rua=mailto:a@example.com", Type = DnsRecordType.TXT },
                new DnsAnswer { DataRaw = "v=TLSRPTv1;rua=mailto:b@example.com", Type = DnsRecordType.TXT }
            };
            var analysis = new TLSRPTAnalysis();
            await analysis.AnalyzeTlsRptRecords(answers, new InternalLogger());

            Assert.True(analysis.MultipleRecords);
            Assert.True(analysis.PolicyValid);
        }

        [Fact]
        public async Task ValidRecordHasNoUnknownTags() {
            var record = "v=TLSRPTv1;rua=mailto:reports@example.com";
            var analysis = new TLSRPTAnalysis();
            await analysis.AnalyzeTlsRptRecords(new[] { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } }, new InternalLogger());

            Assert.Empty(analysis.UnknownTags);
            Assert.True(analysis.PolicyValid);
        }
    }
}