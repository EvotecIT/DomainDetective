using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDANEnalysis {
        [Fact]
        public async Task TestDANERecordByDomain() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            healthCheck.DnsConfiguration.QueryDnsOverride = (name, type) => {
                if (type == DnsRecordType.MX && name == "ietf.org") {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "10 mail2.ietf.org." } });
                }
                if (type == DnsRecordType.TLSA && name == "_25._tcp.mail2.ietf.org") {
                    return Task.FromResult(new[] {
                        new DnsAnswer {
                            Name = "_25._tcp.mail2.ietf.org",
                            DataRaw = "3 1 1 " + new string('A', 64),
                            Type = DnsRecordType.TLSA
                        }
                    });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            };
            healthCheck.DaneDnsOverride = healthCheck.DnsConfiguration.QueryDnsOverride;
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
            healthCheck.DaneDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
            healthCheck.DnsConfiguration.QueryDnsOverride = healthCheck.DaneDnsOverride;
            await healthCheck.VerifyDANE("ipv6.google.com", [ServiceType.HTTPS]);

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
            var healthCheck = new DomainHealthCheck(internalLogger: logger) {
                Verbose = false,
                DnsEndpoint = DnsEndpoint.System
            };
            healthCheck.DaneDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
            healthCheck.DnsConfiguration.QueryDnsOverride = healthCheck.DaneDnsOverride;
            await healthCheck.VerifyDANE("ipv6.google.com", [ServiceType.HTTPS]);

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
            healthCheck.DaneDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());

            await healthCheck.VerifyDANE([new ServiceDefinition("example.com", 443)]);

            Assert.NotNull(healthCheck.DaneAnalysis);
        }

        [Fact]
        public async Task EmptyServiceTypesDefaultsToSmtpHttps() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            healthCheck.DnsConfiguration.QueryDnsOverride = (name, type) => {
                if (type == DnsRecordType.MX && name == "ietf.org") {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "10 mail2.ietf.org." } });
                }
                if (type == DnsRecordType.TLSA && name == "_25._tcp.mail2.ietf.org") {
                    return Task.FromResult(new[] {
                        new DnsAnswer {
                            Name = "_25._tcp.mail2.ietf.org",
                            DataRaw = "3 1 1 " + new string('A', 64),
                            Type = DnsRecordType.TLSA
                        }
                    });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            };
            healthCheck.DaneDnsOverride = healthCheck.DnsConfiguration.QueryDnsOverride;

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
        public async Task InvalidCombinationsAreRejected() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };

            var sha256 = new string('A', 64);
            var invalid = new[] {
                $"4 1 1 {sha256}",
                $"1 2 1 {sha256}",
                $"1 1 3 {sha256}",
                "-1 0 0 ABCD"
            };

            foreach (var record in invalid) {
                await healthCheck.CheckDANE(record);
                var analysis = healthCheck.DaneAnalysis.AnalysisResults[0];
                Assert.False(analysis.ValidDANERecord, record);
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
        public async Task CheckDaneHonorsCancellation() {
            var healthCheck = new DomainHealthCheck();
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await healthCheck.CheckDANE("3 1 1 " + new string('A', 64), cts.Token));
        }

        [Fact]
        public async Task VerifyDaneHonorsCancellation() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            using var cts = new CancellationTokenSource();
            healthCheck.DnsConfiguration.QueryDnsOverride = (name, type) =>
                Task.Delay(Timeout.Infinite, cts.Token).ContinueWith(_ => Array.Empty<DnsAnswer>(), cts.Token);
            healthCheck.DaneDnsOverride = healthCheck.DnsConfiguration.QueryDnsOverride;

            var task = healthCheck.VerifyDANE("example.com", new[] { 443 }, cts.Token);
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
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
            await analysis.AnalyzeDANERecords(answers, new InternalLogger(), CancellationToken.None);

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
            await analysis.AnalyzeDANERecords(answers, logger, CancellationToken.None);

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
            await analysis.AnalyzeDANERecords(answers, new InternalLogger(), CancellationToken.None);

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
            await analysis.AnalyzeDANERecords(answers, new InternalLogger(), CancellationToken.None);

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
            await analysis.AnalyzeDANERecords(answers, logger, CancellationToken.None);

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
            await analysis.AnalyzeDANERecords(answers, logger, CancellationToken.None);

            Assert.Contains(warnings, w => w.FullMessage.Contains("usage '4' is invalid"));
        }

        [Fact]
        public async Task ServiceTypeDefaultsToHttps() {
            var record = "3 1 1 " + new string('A', 64);
            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(new[] { new DnsAnswer { DataRaw = record } }, new InternalLogger(), CancellationToken.None);

            Assert.Equal(ServiceType.HTTPS, analysis.AnalysisResults[0].ServiceType);
        }

        [Fact]
        public async Task UdpNamesAreRecognized() {
            var answers = new[] {
                new DnsAnswer {
                    Name = "_443._udp.example.com",
                    DataRaw = $"3 1 1 {new string('A', 64)}",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(answers, new InternalLogger(), CancellationToken.None);

            var result = analysis.AnalysisResults[0];
            Assert.True(result.ValidDANERecord);
            Assert.Equal(ServiceType.HTTPS, result.ServiceType);
        }

        [Fact]
        public async Task NonDefaultPortIsPreserved() {
            var answers = new[] {
                new DnsAnswer {
                    Name = "_444._tcp.example.com",
                    DataRaw = $"3 1 1 {new string('A', 64)}",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(answers, new InternalLogger(), CancellationToken.None);

            var result = analysis.AnalysisResults[0];
            Assert.True(result.ValidDANERecord);
            Assert.Equal((ServiceType)444, result.ServiceType);
        }

        [Fact]
        public async Task NonNumericPortDefaultsToHttps() {
            var answers = new[] {
                new DnsAnswer {
                    Name = "_smtp._tcp.example.com",
                    DataRaw = $"3 1 1 {new string('A', 64)}",
                    Type = DnsRecordType.TLSA
                }
            };

            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(answers, new InternalLogger(), CancellationToken.None);

            var result = analysis.AnalysisResults[0];
            Assert.True(result.ValidDANERecord);
            Assert.Equal(ServiceType.HTTPS, result.ServiceType);
        }

        [Fact]
        public async Task MultipleRecordsAreValidated() {
            var records = new[] {
                $"3 1 1 {new string('A', 64)}",
                $"3 1 1 {new string('B', 64)}"
            };

            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.CheckDANE(records);

            Assert.Equal(2, healthCheck.DaneAnalysis.NumberOfRecords);
            Assert.False(healthCheck.DaneAnalysis.HasInvalidRecords);
            Assert.Equal(2, healthCheck.DaneAnalysis.AnalysisResults.Count);
        }

        [Fact]
        public async Task EnumValuesAreReturned() {
            var record = $"3 1 1 {new string('A', 64)}";
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.CheckDANE(record);

            var result = healthCheck.DaneAnalysis.AnalysisResults[0];
            Assert.Equal(TlsaUsage.DaneEe, result.CertificateUsage);
            Assert.Equal(TlsaSelector.Spki, result.SelectorField);
            Assert.Equal(TlsaMatchingType.Sha256, result.MatchingTypeField);
        }

        [Fact]
        public void EnumDescriptionsAreAvailable() {
            Assert.Equal(
                "PKIX-TA: CA Constraint",
                TlsaUsage.PkixTa.GetDescription());
            Assert.Equal(
                "SPKI: SubjectPublicKeyInfo",
                TlsaSelector.Spki.GetDescription());
            Assert.Equal(
                "SHA-256: SHA-256 of Certificate or SPKI",
                TlsaMatchingType.Sha256.GetDescription());
        }

        [Fact]
        public async Task SyntaxValidationDoesNotClaimCertificateMatch() {
            var record = new DnsAnswer {
                Name = "_443._tcp.example.com",
                Type = DnsRecordType.TLSA,
                DataRaw = $"3 1 1 {new string('0', 64)}"
            };
            var analysis = new DANEAnalysis();

            await analysis.AnalyzeDANERecords(new[] { record }, new InternalLogger());

            var result = Assert.Single(analysis.AnalysisResults);
            Assert.True(result.ValidDANERecord);
            Assert.Equal(DaneAssociationMatchStatus.NotChecked, result.AssociationMatchStatus);
            Assert.False(result.CertificateMatches);
            Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == DaneCodes.CertificateMatches);
        }

        [Fact]
        public async Task SpkiSha256AssociationMatchesLiveCertificateEvidence() {
            using var certificate = CreateDaneCertificate();
            var spki = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certificate.RawData)
                .CertificateStructure.SubjectPublicKeyInfo.GetEncoded();
            string digest;
            using (var sha256 = SHA256.Create()) {
                digest = BitConverter.ToString(sha256.ComputeHash(spki)).Replace("-", string.Empty);
            }
            var owner = "_443._tcp.example.com";
            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(new[] {
                new DnsAnswer { Name = owner, Type = DnsRecordType.TLSA, DataRaw = $"3 1 1 {digest}" }
            }, new InternalLogger());

            analysis.ValidateCertificateAssociations(new[] {
                new DaneCertificateEvidence {
                    TlsaOwnerName = owner,
                    EndEntityCertificate = certificate,
                    CertificateChain = new[] { certificate },
                    DnssecValidated = true,
                    PkixValidated = false
                }
            }, new InternalLogger());

            var result = Assert.Single(analysis.AnalysisResults);
            Assert.Equal(DaneAssociationMatchStatus.Match, result.AssociationMatchStatus);
            Assert.True(result.CertificateMatches);
            Assert.True(analysis.AllCertificateAssociationsMatch);
            Assert.Contains(analysis.Assessments, assessment => assessment.Code == DaneCodes.CertificateMatches);
        }

        [Fact]
        public async Task AssociationMismatchIsNotReportedAsValidCertificateEvidence() {
            using var certificate = CreateDaneCertificate();
            var owner = "_443._tcp.example.com";
            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(new[] {
                new DnsAnswer { Name = owner, Type = DnsRecordType.TLSA, DataRaw = $"3 1 1 {new string('0', 64)}" }
            }, new InternalLogger());

            analysis.ValidateCertificateAssociations(new[] {
                new DaneCertificateEvidence {
                    TlsaOwnerName = owner,
                    EndEntityCertificate = certificate,
                    CertificateChain = new[] { certificate },
                    DnssecValidated = true
                }
            }, new InternalLogger());

            var result = Assert.Single(analysis.AnalysisResults);
            Assert.Equal(DaneAssociationMatchStatus.NoMatch, result.AssociationMatchStatus);
            Assert.False(result.CertificateMatches);
            Assert.False(analysis.AllCertificateAssociationsMatch);
            Assert.Contains(analysis.Assessments, assessment => assessment.Code == DaneCodes.CertificateMismatch);
        }

        [Fact]
        public async Task UnvalidatedDnssecPreventsAssociationClaim() {
            using var certificate = CreateDaneCertificate();
            var owner = "_443._tcp.example.com";
            var analysis = new DANEAnalysis();
            await analysis.AnalyzeDANERecords(new[] {
                new DnsAnswer { Name = owner, Type = DnsRecordType.TLSA, DataRaw = $"3 0 1 {new string('0', 64)}" }
            }, new InternalLogger());

            analysis.ValidateCertificateAssociations(new[] {
                new DaneCertificateEvidence {
                    TlsaOwnerName = owner,
                    EndEntityCertificate = certificate,
                    CertificateChain = new[] { certificate },
                    DnssecValidated = false
                }
            }, new InternalLogger());

            Assert.Equal(DaneAssociationMatchStatus.CheckFailed, analysis.AnalysisResults[0].AssociationMatchStatus);
            Assert.Contains(analysis.Assessments, assessment => assessment.Code == DaneCodes.DnssecNotValidated);
        }

        [Fact]
        public async Task VerifyDaneUsesCertificateEvidenceProviderEndToEnd() {
            using var certificate = CreateDaneCertificate();
            var spki = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certificate.RawData)
                .CertificateStructure.SubjectPublicKeyInfo.GetEncoded();
            string digest;
            using (var sha256 = SHA256.Create()) {
                digest = BitConverter.ToString(sha256.ComputeHash(spki)).Replace("-", string.Empty);
            }
            var healthCheck = new DomainHealthCheck();
            healthCheck.DaneDnsOverride = (name, type) => Task.FromResult(
                name == "_443._tcp.example.com" && type == DnsRecordType.TLSA
                    ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = $"3 1 1 {digest}" } }
                    : Array.Empty<DnsAnswer>());
            healthCheck.DaneCertificateEvidenceOverride = (host, port, _) => Task.FromResult<DaneCertificateEvidence?>(new DaneCertificateEvidence {
                EndEntityCertificate = certificate,
                CertificateChain = new[] { certificate },
                PkixValidated = true,
                DnssecValidated = true
            });

            await healthCheck.VerifyDANE("example.com", new[] { 443 });

            var result = Assert.Single(healthCheck.DaneAnalysis.AnalysisResults);
            Assert.Equal(DaneAssociationMatchStatus.Match, result.AssociationMatchStatus);
            Assert.True(healthCheck.DaneAnalysis.AllCertificateAssociationsMatch);
        }

        private static X509Certificate2 CreateDaneCertificate() {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }
    }
}
