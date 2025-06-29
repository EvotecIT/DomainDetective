using System.Linq;
using DomainDetective;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestFilterServersConcurrency {
        [Fact]
        public async Task FilterServersHandlesConcurrency() {
            var file = "Data/DNS/PublicDNS.json";
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadServers(file, clearExisting: true);

            var tasks = Enumerable.Range(0, 20)
                .Select(_ => Task.Run(() => analysis.FilterServers(take: 5).ToList()));

            await Task.WhenAll(tasks);
        }
    }
}
