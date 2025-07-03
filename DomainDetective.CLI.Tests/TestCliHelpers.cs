using System;
using System.IO;
using System.Runtime.InteropServices;
using DomainDetective.CLI;

namespace DomainDetective.CLI.Tests {
    public class TestCliHelpers {
        [Fact]
        public void ReadLineRaw_PreservesCarriageReturn() {
            var original = Console.In;
            using var reader = new StringReader("value\r\n");
            Console.SetIn(reader);
            try {
                var line = CliHelpers.ReadLineRaw();
                Assert.Equal("value\r\n", line);
            } finally {
                Console.SetIn(original);
            }
        }
    }
}
