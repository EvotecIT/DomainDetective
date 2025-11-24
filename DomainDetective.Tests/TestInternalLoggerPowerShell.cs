using DomainDetective;
using DomainDetective.PowerShell;
using System.Collections.Generic;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace DomainDetective.Tests {
    public class TestInternalLoggerPowerShell {
        [Fact(Skip = "PowerShell-dependent; skipped in cross-platform runs")]
        public void ErrorRecordIdIncrements() {
            if (!IsWindows()) {
                return;
            }
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

        [Fact(Skip = "PowerShell-dependent; skipped in cross-platform runs")]
        public void ProgressActivityIdIncrements() {
            if (!IsWindows()) {
                return;
            }
            var logger = new InternalLogger();
            var progress = new List<ProgressRecord>();
            var psLogger = new InternalLoggerPowerShell(logger, null, null, null, null, progress.Add);

            logger.WriteProgress("PortScan", "80", 50, 1, 2);
            logger.WriteProgress("PortScan", "80", 100, 2, 2);
            logger.WriteProgress("PortScan", "443", 50, 1, 2);
            logger.WriteProgress("PortScan", "443", 100, 2, 2);

            Assert.Equal(4, progress.Count);
            Assert.Equal(1, progress[0].ActivityId);
            Assert.Equal(1, progress[1].ActivityId);
            Assert.Equal(2, progress[2].ActivityId);
            Assert.Equal(2, progress[3].ActivityId);
            Assert.Equal(ProgressRecordType.Completed, progress[1].RecordType);
            Assert.Equal(ProgressRecordType.Completed, progress[3].RecordType);
        }

        private static bool IsWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
    }
}
