using DnsClientX;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestContactInfoAnalysis {
        [Fact]
        public async Task ParseContactRecord() {
            var record = "email=admin@example.com; phone=12345";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckContactInfo(record);

            Assert.True(healthCheck.ContactInfoAnalysis.RecordExists);
            Assert.Equal("admin@example.com", healthCheck.ContactInfoAnalysis.Fields["email"]);
            Assert.Equal("12345", healthCheck.ContactInfoAnalysis.Fields["phone"]);
            Assert.Contains(healthCheck.ContactInfoAnalysis.Assessments, a => a.Code == ContactCodes.RecordFound);
            Assert.Contains(healthCheck.ContactInfoAnalysis.Assessments, a => a.Code == ContactCodes.FieldsWellFormed);
        }
    }
}
