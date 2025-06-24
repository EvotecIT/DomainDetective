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
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.Verify("ipv6.google.com", [HealthCheckType.DANE], daneServiceType: [ServiceType.HTTPS]);

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(0, healthCheck.DaneAnalysis.NumberOfRecords);
        }

        [Fact]
        public async Task HttpsQueriesAandAaaaRecordsUsingSystemResolver() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false,
                DnsEndpoint = DnsEndpoint.System
            };
            await healthCheck.Verify("ipv6.google.com", [HealthCheckType.DANE], daneServiceType: [ServiceType.HTTPS]);

            Assert.False(healthCheck.DaneAnalysis.HasDuplicateRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(0, healthCheck.DaneAnalysis.NumberOfRecords);
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
    }
}