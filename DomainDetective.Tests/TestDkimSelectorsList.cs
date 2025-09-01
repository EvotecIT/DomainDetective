using DomainDetective.Definitions;
using System.Linq;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDkimSelectorsList {
        [Fact]
        public void GuessSelectorsContainsNewVendors() {
            var list = DKIMSelectors.GuessSelectors().ToArray();
            Assert.Contains("ctct1", list);
            Assert.Contains("ctct2", list);
            Assert.Contains("sig1", list);
            Assert.Contains("litesrv", list);
            Assert.Contains("zendesk1", list);
            Assert.Contains("zendesk2", list);
        }
    }
}

