using DomainDetective;
using System.IO;

namespace DomainDetective.Tests;

public class TestLoadServersNull {
    [Fact]
    public void LoadServersThrowsIfListNull() {
        var file = Path.GetTempFileName();
        try {
            File.WriteAllText(file, "null");
            var analysis = new DnsPropagationAnalysis();
            Assert.Throws<InvalidDataException>(() => analysis.LoadServers(file, clearExisting: true));
        }
        finally {
            File.Delete(file);
        }
    }
}

