using System;
using System.Net;
using System.Text.Json;

namespace DomainDetective.Tests {
    public class TestIPAddressJsonConverter {
        private class Dummy {
            public IPAddress Address { get; set; }
        }

        [Fact]
        public void InvalidAddressReportsIndex() {
            var options = new JsonSerializerOptions { Converters = { new IPAddressJsonConverter() } };
            var json = "{\"Address\":\"bad ip\"}";
            var ex = Assert.Throws<FormatException>(() => JsonSerializer.Deserialize<Dummy>(json, options));
            Assert.Contains("bad ip", ex.Message);
            Assert.Contains("index 11", ex.Message);
        }
    }
}

