namespace DomainDetective {
    public readonly struct ServiceDefinition {
        public ServiceDefinition(string host, int port) {
            Host = host;
            Port = port;
        }

        public string Host { get; }
        public int Port { get; }
    }
}
