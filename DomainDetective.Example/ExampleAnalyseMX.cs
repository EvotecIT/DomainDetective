using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseMX() {

        var mxRecord = "10 evotec-pl.mail.protection.outlook.com";
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = true;
        await healthCheck.CheckMX(mxRecord);
        //ShowProperties("MX for EXAMPLE1 " + mxRecord, healthCheck.MXAnalysis);
        Helpers.ShowPropertiesTable("MX for EXAMPLE1 " + mxRecord, healthCheck.MXAnalysis);
    }
}