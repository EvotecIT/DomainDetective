using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDANEnalysis {
        [Fact]
        public async void TestDANERecordByDomain() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.Verify("ietf.org", new[] { HealthCheckType.DANE });

            Assert.True(healthCheck.DaneAnalysis.HasDuplicateRecords == false);
            Assert.True(healthCheck.DaneAnalysis.HasInvalidRecords == false);
            Assert.True(healthCheck.DaneAnalysis.NumberOfRecords == 1);

            var daneRecord = healthCheck.DaneAnalysis.AnalysisResults[0];
            Assert.True(daneRecord.ValidCertificateAssociationData);
            Assert.True(daneRecord.IsValidChoiceForSmtp);
            Assert.True(daneRecord.ValidMatchingType);
            Assert.True(daneRecord.ValidDANERecord);
            Assert.True(daneRecord.ValidSelector);
            Assert.True(daneRecord.DomainName == "_25._tcp.mail.ietf.org");



        }

        [Fact]
        public async void TestDANERecordByString() {
            var daneRecord = "3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B566 64C5D3D6";
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.CheckDANE(daneRecord);

            Assert.True(healthCheck.DaneAnalysis.HasDuplicateRecords == false);
            Assert.True(healthCheck.DaneAnalysis.HasInvalidRecords == true);
            Assert.True(healthCheck.DaneAnalysis.NumberOfRecords == 1);
        }
    }
}
