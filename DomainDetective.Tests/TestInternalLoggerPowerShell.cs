using DomainDetective;
using DomainDetective.PowerShell;
using System.Collections.Generic;
using System.Management.Automation;

namespace DomainDetective.Tests {
    public class TestInternalLoggerPowerShell {
        [Fact]
        public void ErrorRecordIdIncrements() {
            var logger = new InternalLogger();
            var records = new List<ErrorRecord>();
            var psLogger = new InternalLoggerPowerShell(logger, null, null, null, records.Add);

            logger.WriteError("first");
            logger.WriteError("second");

            Assert.Equal(2, records.Count);
            Assert.Equal("1", records[0].FullyQualifiedErrorId);
            Assert.Equal("first", records[0].ErrorDetails.Message);
            Assert.Equal("2", records[1].FullyQualifiedErrorId);
            Assert.Equal("second", records[1].ErrorDetails.Message);
        }
    }
}