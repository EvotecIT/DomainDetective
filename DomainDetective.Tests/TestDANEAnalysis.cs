using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDANEnalysis {
        [Fact]
        public async Task TestDANERecordByDomain() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.Verify("ietf.org", new[] { HealthCheckType.DANE });

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(1, healthCheck.DaneAnalysis.NumberOfRecords);

            var daneRecord = healthCheck.DaneAnalysis.AnalysisResults[0];
            Assert.True(daneRecord.ValidCertificateAssociationData);
            Assert.True(daneRecord.IsValidChoiceForSmtp);
            Assert.True(daneRecord.ValidMatchingType);
            Assert.True(daneRecord.ValidDANERecord);
            Assert.True(daneRecord.ValidSelector);
            Assert.Equal("_25._tcp.mail2.ietf.org", daneRecord.DomainName);
        }

        [Fact]
        public async Task TestDANERecordByString() {
            var daneRecord = "3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B566 64C5D3D6";
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.CheckDANE(daneRecord);

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.True(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(1, healthCheck.DaneAnalysis.NumberOfRecords);
        }

        [Fact]
        public async Task TestType0RecordVariableLength() {
            var daneRecord = "0 0 0 ABCDEF0123";
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.CheckDANE(daneRecord);

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(1, healthCheck.DaneAnalysis.NumberOfRecords);

            var analysis = healthCheck.DaneAnalysis.AnalysisResults[0];
            Assert.True(analysis.ValidDANERecord);
            Assert.True(analysis.CorrectLengthOfCertificateAssociationData);
            Assert.Equal(10, analysis.LengthOfCertificateAssociationData);
        }

        [Fact]
        public async Task TestRecordWithTrailingSpaceTrimmed() {
            var daneRecord = $"3 1 1 {new string('A', 64)} ";
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.CheckDANE(daneRecord);

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(1, healthCheck.DaneAnalysis.NumberOfRecords);

            var analysis = healthCheck.DaneAnalysis.AnalysisResults[0];
            Assert.True(analysis.ValidDANERecord);
            Assert.True(analysis.CorrectLengthOfCertificateAssociationData);
            Assert.Equal(64, analysis.LengthOfCertificateAssociationData);
        }

        [Fact]
        public async Task HttpsQueriesAandAaaaRecords() {
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(internalLogger: logger) {
                Verbose = false
            };
            await healthCheck.Verify("ipv6.google.com", [HealthCheckType.DANE], daneServiceType: [ServiceType.HTTPS]);

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(0, healthCheck.DaneAnalysis.NumberOfRecords);
            Assert.Contains(warnings, w => w.FullMessage.Contains("No DANE records"));
        }

        [Fact]
        public async Task HttpsQueriesAandAaaaRecordsUsingSystemResolver() {
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(DnsEndpoint.System, logger) {
                Verbose = false
            };
            await healthCheck.Verify("ipv6.google.com", [HealthCheckType.DANE], daneServiceType: [ServiceType.HTTPS]);

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(0, healthCheck.DaneAnalysis.NumberOfRecords);
            Assert.Contains(warnings, w => w.FullMessage.Contains("No DANE records"));
        }

        [Fact]
        public async Task CustomServiceNamesAreSupported() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };

            await healthCheck.VerifyDANE([new ServiceDefinition("example.com", 443)]);

            Assert.NotNull(healthCheck.DaneAnalysis);
        }

        [Fact]
        public async Task EmptyServiceTypesDefaultsToSmtpHttps() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };

            await healthCheck.VerifyDANE("ietf.org", Array.Empty<ServiceType>());

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(1, healthCheck.DaneAnalysis.NumberOfRecords);
        }

        [Fact]
        public async Task AllCombinationsAreConsideredValid() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };

            var sha256 = new string('A', 64);
            var sha512 = new string('A', 128);

            for (var usage = 0; usage <= 3; usage++) {
                for (var selector = 0; selector <= 1; selector++) {
                    for (var matching = 0; matching <= 2; matching++) {
                        var data = matching switch {
                            0 => "ABCD",
                            1 => sha256,
                            2 => sha512,
                            _ => ""
                        };

                        var record = $"{usage} {selector} {matching} {data}";
                        await healthCheck.CheckDANE(record);
                        var analysis = healthCheck.DaneAnalysis.AnalysisResults[0];
                        Assert.True(analysis.ValidDANERecord, record);
                    }
                }
            }
        }

        [Fact]
        public async Task VerifyDaneThrowsIfPortsNull() {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await healthCheck.VerifyDANE("example.com", (int[])null!));
        }

        [Fact]
        public async Task VerifyDaneThrowsIfPortsEmpty() {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await healthCheck.VerifyDANE("example.com", Array.Empty<int>()));
        }

        [Fact]
        public async Task VerifyDaneThrowsIfPortZero() {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await healthCheck.VerifyDANE("example.com", new[] { 0 }));
        }

        [Fact]
        public async Task VerifyDaneThrowsIfPortNegative() {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await healthCheck.VerifyDANE("example.com", new[] { -25 }));
        }

        [Fact]
        public async Task HttpsRecommendedCombinationIsFlagged() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    Name = "_443._tcp.example.com",
                    DataRaw = $"3 1 1 {new string('A', 64)}",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(answers, new InternalLogger());

            Assert.True(analysis.AnalysisResults[0].IsValidChoiceForHttps);
        }

        [Fact]
        public async Task HttpsMismatchIsDetected() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    Name = "_443._tcp.example.com",
                    DataRaw = $"2 0 1 {new string('A', 64)}",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            await analysis.AnalyzeDANERecords(answers, logger);

            Assert.False(analysis.AnalysisResults[0].IsValidChoiceForHttps);
            Assert.Contains(warnings, w => w.FullMessage.Contains("not recommended for HTTPS"));
        }

        [Fact]
        public async Task ValidHttpsRecordIsRecognized() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    Name = "_443._tcp.example.com",
                    DataRaw = $"3 1 1 {new string('A', 64)}",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(answers, new InternalLogger());

            var result = analysis.AnalysisResults[0];
            Assert.True(result.ValidDANERecord);
            Assert.Equal(ServiceType.HTTPS, result.ServiceType);
        }

        [Fact]
        public async Task InvalidHttpsRecordIsFlagged() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    Name = "_443._tcp.example.com",
                    DataRaw = "3 1 1 ABCD",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(answers, new InternalLogger());

            Assert.False(analysis.AnalysisResults[0].ValidDANERecord);
        }

        [Fact]
        public async Task InvalidSelectorOrMatchingTypeTriggersWarning() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    Name = "_25._tcp.example.com",
                    DataRaw = "3 2 5 ABCD",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            await analysis.AnalyzeDANERecords(answers, logger);

            Assert.Contains(warnings, w => w.FullMessage.Contains("selector value"));
            Assert.Contains(warnings, w => w.FullMessage.Contains("matching type"));
        }

        [Fact]
        public async Task InvalidUsageTriggersWarning() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    Name = "_25._tcp.example.com",
                    DataRaw = "4 1 1 ABCD",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            await analysis.AnalyzeDANERecords(answers, logger);

            Assert.Contains(warnings, w => w.FullMessage.Contains("usage '4' is invalid"));
        }

        [Fact]
        public async Task ServiceTypeDefaultsToHttps() {
            var record = "3 1 1 " + new string('A', 64);
            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(new[] { new DnsAnswer { DataRaw = record } }, new InternalLogger());

            Assert.Equal(ServiceType.HTTPS, analysis.AnalysisResults[0].ServiceType);
        }
    }
}