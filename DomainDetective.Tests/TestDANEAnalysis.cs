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
            Assert.Equal("_25._tcp.mail.ietf.org", daneRecord.DomainName);



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
    }
}
