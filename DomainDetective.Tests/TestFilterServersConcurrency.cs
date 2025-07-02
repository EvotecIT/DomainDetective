using System.Linq;
using DomainDetective;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestFilterServersConcurrency {
        [Fact]
        public async Task FilterServersHandlesConcurrency() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();

            var tasks = Enumerable.Range(0, 20)
                .Select(_ => Task.Run(() => analysis.FilterServers(take: 5).ToList()));

            await Task.WhenAll(tasks);
        }
    }
}
