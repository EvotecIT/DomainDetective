using DomainDetective;
using System.Net;

namespace DomainDetective.Tests {
    public class TestDnsPropagationValidation {
        [Fact]
        public void LoadServersThrowsForMissingCountry() {
            var json = "[{\"IPAddress\":\"1.2.3.4\",\"ASN\":\"1234\"}]";
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);
                var analysis = new DnsPropagationAnalysis();
                Assert.Throws<FormatException>(() => analysis.LoadServers(file, clearExisting: true));
            } finally {
                File.Delete(file);
            }
        }

        [Fact]
        public void LoadServersThrowsForMissingAsn() {
            var json = "[{\"Country\":\"US\",\"IPAddress\":\"1.2.3.4\"}]";
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);
                var analysis = new DnsPropagationAnalysis();
                Assert.Throws<FormatException>(() => analysis.LoadServers(file, clearExisting: true));
            } finally {
                File.Delete(file);
            }
        }

        [Fact]
        public void LoadServersThrowsForMissingIp() {
            var json = "[{\"Country\":\"US\",\"ASN\":\"1234\"}]";
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);
                var analysis = new DnsPropagationAnalysis();
                Assert.Throws<FormatException>(() => analysis.LoadServers(file, clearExisting: true));
            } finally {
                File.Delete(file);
            }
        }
    }
}
