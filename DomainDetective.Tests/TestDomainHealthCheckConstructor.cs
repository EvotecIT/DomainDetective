using System;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestDomainHealthCheckConstructor {
        [Fact]
        public void ConstructorThrowsWhenEndpointNull() {
            Assert.Throws<ArgumentNullException>(() => new DomainHealthCheck(default));
        }
    }
}
