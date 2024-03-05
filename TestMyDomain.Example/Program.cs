using System;
using System.Collections;
using System.Threading.Tasks;
using TestMyDomain;

public static partial class Program {
    public static async Task Main() {
        // run the analysis of SPF
        //await ExampleAnalyseSPF();
        // run the analysis of DMARC
        await ExampleAnalyseDMARC();
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