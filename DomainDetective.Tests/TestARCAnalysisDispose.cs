using System.IO;

namespace DomainDetective.Tests {
    public class TestARCAnalysisDispose {
        private class CountingMemoryStream : MemoryStream {
            public static int DisposeCount { get; set; }
            public CountingMemoryStream(byte[] buffer) : base(buffer) { }
            protected override void Dispose(bool disposing) {
                if (disposing) {
                    DisposeCount++;
                }
                base.Dispose(disposing);
            }
        }

        [Fact]
        public void DisposesStreamsWhenParsingFails() {
            var original = ARCAnalysis.CreateStream;
            CountingMemoryStream.DisposeCount = 0;
            ARCAnalysis.CreateStream = b => new CountingMemoryStream(b);
            try {
                var analysis = new ARCAnalysis();
                analysis.Analyze("Invalid-Header");
            } finally {
                ARCAnalysis.CreateStream = original;
            }
            Assert.Equal(2, CountingMemoryStream.DisposeCount);
        }
    }
}
