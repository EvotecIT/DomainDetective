using System;
using System.Collections;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task Main() {
        // run the analysis of SPF
        //await ExampleAnalyseByDnsSPF();
        //await ExampleAnalyseByStringSPF();
        // run the analysis of DMARC
        //await ExampleAnalyseByStringDMARC();
        //await ExampleAnalyseByDomainDMARC();
        // run the analysis of DKIM
        await ExampleAnalyseByStringDKIM();
        await ExampleAnalyseByDomainDKIM();
        // run the analysis of MX
        //await ExampleAnalyseMX();
        // run the analysis of CAA
        //await ExampleAnalyseByDomainCAA();
        //await ExampleAnalyseByStringCAA();
    }

    public static void ShowProperties(string analysisOf, object obj) {
        Console.WriteLine("----");
        Console.WriteLine($"Analysis of {analysisOf}:");
        var properties = obj.GetType().GetProperties();
        foreach (var property in properties) {
            var value = property.GetValue(obj);
            if (value is IList listValue) {
                Console.WriteLine($"- {property.Name}:");
                foreach (var item in listValue) {
                    Console.WriteLine($"  * {item}");
                }
            } else {
                Console.WriteLine($"- {property.Name}: {value}");
            }
        }
    }
}