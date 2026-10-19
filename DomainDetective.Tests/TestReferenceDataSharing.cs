namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestReferenceDataSharing {
    [Fact]
    public void HstsAutomaticLoadTracksSourceVersionAndExplicitLoadRefreshesSameVersion() {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        var bundled = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hsts_preload.json.gz");
        try {
            File.WriteAllText(path, "[\"first.example\"]");
            HttpAnalysis.EnsureHstsPreloadListLoaded(path);
            Assert.True(HttpAnalysis.IsHstsPreloadedHost("first.example"));
            var timestamp = File.GetLastWriteTimeUtc(path);
            File.WriteAllText(path, "[\"other.example\"]"); // same byte length
            File.SetLastWriteTimeUtc(path, timestamp);
            HttpAnalysis.EnsureHstsPreloadListLoaded(path);
            Assert.True(HttpAnalysis.IsHstsPreloadedHost("first.example"));
            Assert.False(HttpAnalysis.IsHstsPreloadedHost("other.example"));
            HttpAnalysis.LoadHstsPreloadList(path);
            Assert.True(HttpAnalysis.IsHstsPreloadedHost("other.example"));
            Assert.False(HttpAnalysis.IsHstsPreloadedHost("first.example"));
            File.WriteAllText(path, "[\"changed.example\"]");
            HttpAnalysis.EnsureHstsPreloadListLoaded(path);
            Assert.True(HttpAnalysis.IsHstsPreloadedHost("changed.example"));
            File.WriteAllText(path, "malformed");
            HttpAnalysis.EnsureHstsPreloadListLoaded(path);
            Assert.True(HttpAnalysis.IsHstsPreloadedHost("changed.example"));
        } finally {
            File.Delete(path);
            if (File.Exists(bundled)) { HttpAnalysis.LoadHstsPreloadList(bundled); }
        }
    }
}
