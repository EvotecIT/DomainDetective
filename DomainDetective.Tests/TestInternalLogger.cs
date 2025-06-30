using DomainDetective;

namespace DomainDetective.Tests {
    public class TestInternalLogger {
        [Fact]
        public void ProgressEventHasCorrectPercentage() {
            var logger = new InternalLogger();
            LogEventArgs? eventArgs = null;
            logger.OnProgressMessage += (_, e) => eventArgs = e;

            logger.WriteProgress("activity", "operation", 42, 2, 5);

            Assert.NotNull(eventArgs);
            Assert.Equal(42, eventArgs!.ProgressPercentage);
            Assert.Equal(2, eventArgs.ProgressCurrentSteps);
            Assert.Equal(5, eventArgs.ProgressTotalSteps);
        }

        [Fact]
        public void ProgressEventHandlesSmallTotals() {
            var logger = new InternalLogger();
            LogEventArgs? eventArgs = null;
            logger.OnProgressMessage += (_, e) => eventArgs = e;

            logger.WriteProgress("activity", "operation", 1 * 100d / 2, 1, 2);
            Assert.NotNull(eventArgs);
            Assert.Equal(50, eventArgs!.ProgressPercentage);

            logger.WriteProgress("activity", "operation", 1 * 100d / 3, 1, 3);
            Assert.Equal(33, eventArgs!.ProgressPercentage);
        }

        [Fact]
        public void VerboseEventRaised() {
            var logger = new InternalLogger();
            LogEventArgs? eventArgs = null;
            logger.OnVerboseMessage += (_, e) => eventArgs = e;

            logger.WriteVerbose("hello");

            Assert.NotNull(eventArgs);
            Assert.Equal("hello", eventArgs!.Message);
        }
    }
}