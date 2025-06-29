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
            var original = ARCAnalysis.StreamFactory;
            CountingMemoryStream.DisposeCount = 0;
            ARCAnalysis.StreamFactory = b => new CountingMemoryStream(b);
            try {
                var analysis = new ARCAnalysis();
                analysis.Analyze("Invalid-Header");
            } finally {
                ARCAnalysis.StreamFactory = original;
            }
            Assert.Equal(2, CountingMemoryStream.DisposeCount);
        }
    }
}
