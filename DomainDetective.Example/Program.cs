using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Spectre.Console;
using Spectre.Console.Rendering;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task Main() {
        // run the analysis of SPF
        await ExampleAnalyseByDnsSPF();
        await ExampleAnalyseByStringSPF();
        // run the analysis of DMARC
        //await ExampleAnalyseByStringDMARC();
        //await ExampleAnalyseByDomainDMARC();
        // run the analysis of DKIM
        //await ExampleAnalyseByStringDKIM();
        //await ExampleAnalyseByDomainDKIM();
        // run the analysis of MX
        //await ExampleAnalyseMX();
        // run the analysis of CAA
        await ExampleAnalyseByDomainCAA();
        await ExampleAnalyseByStringCAA();
    }
}