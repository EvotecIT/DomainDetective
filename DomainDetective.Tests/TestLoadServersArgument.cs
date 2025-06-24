using DomainDetective;

namespace DomainDetective.Tests {
    public class TestLoadServersArgument {
        [Fact]
        public void LoadServersThrowsIfPathNullOrWhitespace() {
            var analysis = new DnsPropagationAnalysis();

            Assert.Throws<ArgumentException>(() => analysis.LoadServers(" ")); 
        }
    }
}

