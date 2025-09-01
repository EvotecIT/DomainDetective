using System;
using System.Collections.Generic;

namespace DomainDetective {
    /// <summary>
    /// Internal logger that allows to write to console, error or wherever else is needed
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Consumers subscribe to events to integrate logging with other systems
    /// while optional console output aids troubleshooting during development.
    /// </remarks>
    public class InternalLogger {
        private readonly object _lock = new object();
        private readonly Dictionary<string, int> _progressSteps = new();
        private readonly HashSet<string> _loggedMessages = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Define Verbose message event
        /// </summary>
        public event EventHandler<LogEventArgs> OnVerboseMessage;

        /// <summary>
        /// Define Warning message event
        /// </summary>
        public event EventHandler<LogEventArgs> OnWarningMessage;

        /// <summary>
        /// Define Error message event
        /// </summary>
        public event EventHandler<LogEventArgs> OnErrorMessage;

        /// <summary>
        /// Define Debug message event
        /// </summary>
        public event EventHandler<LogEventArgs> OnDebugMessage;

        /// <summary>
        /// Define Progress message event
        /// </summary>
        public event EventHandler<LogEventArgs> OnProgressMessage;

        /// <summary>
        /// Define Information message event
        /// </summary>
        public event EventHandler<LogEventArgs> OnInformationMessage;

        /// <summary>
        /// If true, will write verbose messages to console
        /// </summary>
        public bool IsVerbose { get; set; }

        /// <summary>
        /// If true, will write error messages to console
        /// </summary>
        public bool IsError { get; set; }

        /// <summary>
        /// If true, will write warning messages to console
        /// </summary>
        public bool IsWarning { get; set; }

        /// <summary>
        /// If true, will write debug messages to console
        /// </summary>
        public bool IsDebug { get; set; }

        /// <summary>
        /// If true, will write information messages to console
        /// </summary>
        public bool IsInformation { get; set; }

        /// <summary>
        /// if true, will write progress messages to console
        /// </summary>
        public bool IsProgress { get; set; }

        /// <summary>
        /// Initialize logger
        /// </summary>
        /// <param name="isVerbose"></param>
        public InternalLogger(bool isVerbose = false) {
            IsVerbose = isVerbose;
        }

        /// <summary>
        /// Clears cached messages to allow duplicates to be logged again.
        /// </summary>
        public void ClearLoggedMessages() {
            lock (_lock) {
                _loggedMessages.Clear();
            }
        }

        public void WriteProgress(string activity, string currentOperation, double percentCompleted, int? currentSteps = null, int? totalSteps = null) {
            lock (_lock) {
                var roundedPercent = (int)Math.Round(percentCompleted);
                OnProgressMessage?.Invoke(this, new LogEventArgs(activity, currentOperation, currentSteps, totalSteps, roundedPercent));
                if (IsProgress) {
                    var bucket = roundedPercent / 10;
                    if (!_progressSteps.TryGetValue(activity, out var last) || bucket > last) {
                        _progressSteps[activity] = bucket;
                        var percentText = percentCompleted.ToString("F1");
                        if (currentSteps.HasValue && totalSteps.HasValue) {
                            Console.WriteLine(
                                "[progress] activity: {0} / operation: {1} / percent completed: {2}% ({3} out of {4})",
                                activity,
                                currentOperation,
                                percentText,
                                currentSteps,
                                totalSteps);
                        } else {
                            Console.WriteLine(
                                "[progress] activity: {0} / operation: {1} / percent completed: {2}%",
                                activity,
                                currentOperation,
                                percentText);
                        }
                    }
                }
            }
        }

        public void WriteError(string message) {
            lock (_lock) {
                if (!_loggedMessages.Add(message)) {
                    return;
                }
                OnErrorMessage?.Invoke(this, new LogEventArgs(message));
                if (IsError) {
                    Console.WriteLine("[error] " + message);
                }
            }
        }

        public void WriteError(string message, params object[] args) {
            lock (_lock) {
                var formatted = string.Format(message, args);
                if (!_loggedMessages.Add(formatted)) {
                    return;
                }
                OnErrorMessage?.Invoke(this, new LogEventArgs(formatted));
                if (IsError) {
                    Console.WriteLine("[error] " + message, args);
                }
            }
        }

        /// <summary>
        /// Writes an error with a structured code.
        /// </summary>
        public void WriteErrorCode(string code, string message, params object[] args) {
            lock (_lock) {
                var formatted = args != null && args.Length > 0 ? string.Format(message, args) : message;
                if (!_loggedMessages.Add(formatted)) {
                    return;
                }
                OnErrorMessage?.Invoke(this, new LogEventArgs(formatted) { Code = code });
                if (IsError) {
                    Console.WriteLine("[error] " + message, args);
                }
            }
        }

        public void WriteWarning(string message) {
            lock (_lock) {
                if (!_loggedMessages.Add(message)) {
                    return;
                }
                OnWarningMessage?.Invoke(this, new LogEventArgs(message));
                if (IsWarning) {
                    Console.WriteLine("[warning] " + message);
                }
            }
        }

        public void WriteWarning(string message, params object[] args) {
            lock (_lock) {
                var formatted = string.Format(message, args);
                if (!_loggedMessages.Add(formatted)) {
                    return;
                }
                OnWarningMessage?.Invoke(this, new LogEventArgs(formatted));
                if (IsWarning) {
                    Console.WriteLine("[warning] " + message, args);
                }
            }
        }

        /// <summary>
        /// Writes a warning with a structured code.
        /// </summary>
        public void WriteWarningCode(string code, string message, params object[] args) {
            lock (_lock) {
                var formatted = args != null && args.Length > 0 ? string.Format(message, args) : message;
                if (!_loggedMessages.Add(formatted)) {
                    return;
                }
                OnWarningMessage?.Invoke(this, new LogEventArgs(formatted) { Code = code });
                if (IsWarning) {
                    Console.WriteLine("[warning] " + message, args);
                }
            }
        }

        public void WriteVerbose(string message) {
            lock (_lock) {
                if (!_loggedMessages.Add(message)) {
                    return;
                }
                OnVerboseMessage?.Invoke(this, new LogEventArgs(message));
                if (IsVerbose) {
                    Console.WriteLine(message);
                }
            }
        }

        public void WriteVerbose(string message, params object[] args) {
            lock (_lock) {
                var formatted = string.Format(message, args);
                if (!_loggedMessages.Add(formatted)) {
                    return;
                }
                OnVerboseMessage?.Invoke(this, new LogEventArgs(formatted));
                if (IsVerbose) {
                    Console.WriteLine(message, args);
                }
            }
        }

        public void WriteDebug(string message, params object[] args) {
            lock (_lock) {
                var formatted = string.Format(message, args);
                if (!_loggedMessages.Add(formatted)) {
                    return;
                }
                OnDebugMessage?.Invoke(this, new LogEventArgs(formatted));
                if (IsDebug) {
                    Console.WriteLine("[debug] " + message, args);
                }
            }
        }

        public void WriteInformation(string message, params object[] args) {
            lock (_lock) {
                var formatted = string.Format(message, args);
                if (!_loggedMessages.Add(formatted)) {
                    return;
                }
                OnInformationMessage?.Invoke(this, new LogEventArgs(formatted));
                if (IsInformation) {
                    Console.WriteLine("[information] " + message, args);
                }
            }
        }

        /// <summary>
        /// Writes an information message with a structured code.
        /// </summary>
        public void WriteInformationCode(string code, string message, params object[] args) {
            lock (_lock) {
                var formatted = args != null && args.Length > 0 ? string.Format(message, args) : message;
                if (!_loggedMessages.Add(formatted)) {
                    return;
                }
                OnInformationMessage?.Invoke(this, new LogEventArgs(formatted) { Code = code });
                if (IsInformation) {
                    Console.WriteLine("[information] " + message, args);
                }
            }
        }
    }

    /// <summary>
    /// Provides details about a logging event.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class LogEventArgs : EventArgs {
        /// <summary>Optional structured event code.</summary>
        public string? Code { get; set; }
        /// <summary>
        /// Progress percentage
        /// </summary>
        public int? ProgressPercentage { get; set; }

        /// <summary>
        /// Progress total steps
        /// </summary>
        public int? ProgressTotalSteps { get; set; }

        /// <summary>
        /// Progress current steps
        /// </summary>
        public int? ProgressCurrentSteps { get; set; }

        /// <summary>
        /// Progress current operation
        /// </summary>
        public string ProgressCurrentOperation { get; set; }

        /// <summary>
        /// Progress activity
        /// </summary>
        public string ProgressActivity { get; set; }

        /// <summary>
        /// Message to be written including arguments substitution
        /// </summary>
        public string FullMessage { get; set; }

        /// <summary>
        /// Message to be written
        /// </summary>
        public string Message { get; set; }

        public object[] Args { get; set; }

        public LogEventArgs(string message, object[] args) {
            Message = message;
            Args = args;
            FullMessage = string.Format(message, args);
        }

        public LogEventArgs(string message) {
            Message = message;
            FullMessage = message;
        }

        public LogEventArgs(string activity, string currentOperation, int? currentSteps, int? totalSteps, int? percentage) {
            ProgressActivity = activity;
            ProgressCurrentOperation = currentOperation;
            ProgressCurrentSteps = currentSteps;
            ProgressTotalSteps = totalSteps;
            ProgressPercentage = percentage;
        }
    }
}
