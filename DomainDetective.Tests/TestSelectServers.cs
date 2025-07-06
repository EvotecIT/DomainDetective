using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestSelectServers {
        [Fact]
        public void SelectServersReturnsRequestedCounts() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var servers = analysis.SelectServers(new Dictionary<string, int> { ["PL"] = 2, ["DE"] = 1 });
            Assert.Equal(3, servers.Count);
            Assert.Equal(2, servers.Count(s => s.Country == "Poland"));
            Assert.Equal(1, servers.Count(s => s.Country == "Germany"));
        }
    }
}
