using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestDownloadTrustAnchors {
        [Fact]
        public async Task FetchesAnchors() {
            var anchors = await DnsSecAnalysis.DownloadTrustAnchors();
            Assert.NotEmpty(anchors);
        }
    }
}
