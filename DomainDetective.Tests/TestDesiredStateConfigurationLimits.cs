using System;
using System.IO;
using DomainDetective.DesiredState;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestDesiredStateConfigurationLimits {
    [Fact]
    public void Load_Throws_WhenVersionIsTooNew() {
        var json = @"{ ""version"": 99, ""defaults"": { } }";
        var path = Path.Combine(Path.GetTempPath(), $"desired-state-version-{Guid.NewGuid():N}.json");
        try {
            File.WriteAllText(path, json);
            var ex = Assert.Throws<InvalidOperationException>(() => DesiredStateConfiguration.Load(path));
            Assert.Contains("newer than supported version", ex.Message, StringComparison.OrdinalIgnoreCase);
        } finally {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void Load_Throws_WhenFileExceedsMaxSize() {
        var path = Path.Combine(Path.GetTempPath(), $"desired-state-{Guid.NewGuid():N}.json");
        try {
            var bytes = new byte[(1024 * 1024) + 1];
            File.WriteAllBytes(path, bytes);

            var ex = Assert.Throws<InvalidOperationException>(() => DesiredStateConfiguration.Load(path));
            Assert.Contains("too large", ex.Message, StringComparison.OrdinalIgnoreCase);
        } finally {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        }
    }
}
