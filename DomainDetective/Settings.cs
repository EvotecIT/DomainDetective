namespace DomainDetective {

    /// <summary>
    /// Base settings used across DomainDetective components.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class Settings {
        protected static InternalLogger _logger = new InternalLogger();

        /// <summary>
        /// Gets or sets a value indicating whether error messages are written.
        /// </summary>
        public bool Error {
            get => _logger.IsError;
            set => _logger.IsError = value;
        }

        /// <summary>
        /// Gets or sets a value indicating whether verbose messages are written.
        /// </summary>
        public bool Verbose {
            get => _logger.IsVerbose;
            set => _logger.IsVerbose = value;
        }

        /// <summary>
        /// Gets or sets a value indicating whether warning messages are written.
        /// </summary>
        public bool Warning {
            get => _logger.IsWarning;
            set => _logger.IsWarning = value;
        }

        /// <summary>
        /// Gets or sets a value indicating whether progress messages are written.
        /// </summary>
        public bool Progress {
            get => _logger.IsProgress;
            set => _logger.IsProgress = value;
        }

        /// <summary>
        /// Gets or sets a value indicating whether debug messages are written.
        /// </summary>
        public bool Debug {
            get => _logger.IsDebug;
            set => _logger.IsDebug = value;
        }

        /// <summary>
        /// Number of threads to use for lingering object detection.
        /// </summary>
        public int NumberOfThreads = 8;

        protected readonly object _LockObject = new object();
    }
}