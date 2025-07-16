using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates deserializing RDAP JSON into strongly typed objects.
    /// </summary>
    public static async Task ExampleDeserializeRdap()
    {
        var hc = new DomainHealthCheck { Verbose = false };
        await hc.QueryRDAP("example.com");
        if (hc.RdapAnalysis.DomainData is {} domain)
        {
            Helpers.ShowPropertiesTable("RDAP domain data", domain);
        }
    }
}
