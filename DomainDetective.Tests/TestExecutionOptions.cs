using DomainDetective;

namespace DomainDetective.Tests {
    public class TestExecutionOptions {
        [Fact]
        public void DefaultsEnableParallelism() {
            var options = new HealthCheckExecutionOptions();
            Assert.True(options.EnableParallelism);
        }

        [Fact]
        public void EffectiveParallelismUsesOverrides() {
            var options = new HealthCheckExecutionOptions {
                MaxParallelism = 7,
                DnsParallelism = 5
            };

            Assert.Equal(7, options.GetEffectiveMaxParallelism());
            Assert.Equal(5, options.GetEffectiveDnsParallelism());
        }

        [Fact]
        public void EffectiveParallelismIsClamped() {
            var options = new HealthCheckExecutionOptions();
            var max = options.GetEffectiveMaxParallelism();
            var dns = options.GetEffectiveDnsParallelism();

            Assert.InRange(max, 4, 32);
            Assert.InRange(dns, 4, 32);
        }
    }
}
