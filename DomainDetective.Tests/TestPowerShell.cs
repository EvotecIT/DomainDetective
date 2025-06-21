using System.Management.Automation;

namespace DomainDetective.Tests {
    public class TestPowerShell {
        [Fact]
        public void InvokeNsCmdlet() {
            using var ps = System.Management.Automation.PowerShell.Create();
            ps.AddCommand("Import-Module").AddParameter("Assembly", typeof(DomainDetective.PowerShell.CmdletTestNsRecord).Assembly);
            ps.Invoke();
            ps.Commands.Clear();
            ps.AddCommand("Test-NsRecord").AddParameter("DomainName", "example.com");
            var results = ps.Invoke();
            Assert.Single(results);
        }
    }
}
