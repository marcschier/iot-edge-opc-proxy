﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Azure.Devices.Proxy {
    using System;
    using System.Diagnostics;
    using System.Diagnostics.Tracing;
    using System.Globalization;
    using Provider;
    using Relay;

    /// <summary>
    /// EventSource for the new Dynamic EventSource type of Microsoft-Azure-Devices-Proxy traces.
    /// </summary>
    [EventSource(Name = "Microsoft-Azure-Devices-Proxy")]
    internal class ProxyEventSource : EventSource {
        public static readonly ProxyEventSource Log = new ProxyEventSource();

        // Prevent additional instances other than ProxyEventSource.Log
        ProxyEventSource() {
        }

        public class Keywords   // This is a bitvector
        {
            public const EventKeywords Client = (EventKeywords)0x0001;
            public const EventKeywords Proxy = (EventKeywords)0x0002;
        }


        [Event(40190, Message = "Listener started: Source: {0}.")]
        public void LocalListenerStarted(object source) {
            if (this.IsEnabled()) {
                this.WriteEvent(40190, CreateSourceString(source));
            }
            Trace.TraceInformation($"Listener started ({source}).");
        }

        [Event(40191, Message = "Connection accepted: {0}.")]
        public void ConnectionAccepted(object source) {
            if (this.IsEnabled()) {
                this.WriteEvent(40191, CreateSourceString(source));
            }
        }

        [Event(40192, Message = "Connection rejected: {0} - {1}.")]
        public void ConnectionRejected(object source, Exception e) {
            if (this.IsEnabled()) {
                this.WriteEvent(40192, CreateSourceString(source), ExceptionToString(e));
            }
            Trace.TraceError($"Connection rejected... ({source}). {ExceptionToString(e)}");
        }

        [Event(40193, Message = "Stream Exception: {0} - {1} - {2}.")]
        public void StreamException(object source, object stream, Exception e) {
            if (this.IsEnabled()) {
                this.WriteEvent(40193, CreateSourceString(source), 
                    CreateSourceString(stream), ExceptionToString(e));
            }
            Trace.TraceInformation($"Stream error: {stream} ... ({source}). {ExceptionToString(e)}");
        }

        [Event(40194, Message = "Stream opened: {0} - {1}.")]
        public void StreamOpened(object source, object stream) {
            if (this.IsEnabled()) {
                this.WriteEvent(40194, CreateSourceString(source), CreateSourceString(stream));
            }
            Trace.TraceInformation($"Stream opened: {stream} ... ({source}).");
        }

        [Event(40195, Message = "Stream closing: {0} - {1}.")]
        public void StreamClosing(object source, object stream) {
            if (this.IsEnabled()) {
                this.WriteEvent(40195, CreateSourceString(source), CreateSourceString(stream));
            }
            Trace.TraceInformation($"Stream closing: {stream} ... ({source}).");
        }

        [Event(40196, Message = "Stream closed: {0} - {1}.")]
        public void StreamClosed(object source, object stream) {
            if (this.IsEnabled()) {
                this.WriteEvent(40196, CreateSourceString(source), CreateSourceString(stream));
            }
            Trace.TraceInformation($"Stream closed: {stream} ... ({source}).");
        }

        // 40197 - 40198 Available

        [Event(40199, Message = "Listener closed: Source: {0}.")]
        public void LocalListenerClosed(object source) {
            if (this.IsEnabled()) {
                this.WriteEvent(40199, CreateSourceString(source));
            }
            Trace.TraceInformation($"Listener closed ({source}).");
        }


        // 40200 - 40219 Available

        [Event(40220, Level = EventLevel.Error, Message = "{0} No proxies installed on IoT Hub.")]
        public void NoProxyInstalled(object source) {
            if (this.IsEnabled()) {
                this.WriteEvent(40210, CreateSourceString(source));
            }
            Trace.TraceError($"No proxies installed - Add proxies to IoT Hub! ({source})");
        }

        // 40221 - 40247 Available


        [Event(40248, Level = EventLevel.Warning, Message = "{0} Retry {1} after exception: {2}")]
        public void Retry(object source, int k, Exception ex) {
            if (this.IsEnabled()) {
                this.WriteEvent(40248, source, k, ExceptionToString(ex));
            }
            Trace.TraceInformation($"{source} Retry {k} after exception: {ex.ToString()}");
        }

        // Not the actual event definition since we're using object and Exception types
        [NonEvent]
        public void HandledExceptionAsInformation(object source, Exception exception) {
            this.HandledExceptionAsInformation(CreateSourceString(source), ExceptionToString(exception));
            Trace.TraceInformation($"IGNORING {exception.Message} ({source}).");
        }

        [Event(40249, Message = "{0} Handled Exception: {1}")]
        void HandledExceptionAsInformation(string source, string exception) {
            if (this.IsEnabled()) {
                this.WriteEvent(40249, source, exception);
            }
        }

        // Not the actual event definition since we're using object and Exception types
        [NonEvent]
        public void HandledExceptionAsWarning(object source, Exception exception) {
            this.HandledExceptionAsWarning(CreateSourceString(source), ExceptionToString(exception));
        }

        [Event(40250, Level = EventLevel.Warning, Message = "{0} Handled Exception: {1}")]
        void HandledExceptionAsWarning(string source, string exception) {
            if (this.IsEnabled()) {
                this.WriteEvent(40250, source, exception);
            }
            Trace.TraceWarning($"WARNING CONTINUE: {exception} ({source}).");
        }

        // Not the actual event definition since we're using object and Exception types
        [NonEvent]
        public void HandledExceptionAsError(object source, Exception exception) {
            this.HandledExceptionAsError(CreateSourceString(source), ExceptionToString(exception));
        }

        [Event(40251, Level = EventLevel.Error, Message = "{0} Handled Exception: {1}")]
        void HandledExceptionAsError(string source, string exception) {
            if (this.IsEnabled()) {
                this.WriteEvent(40251, source, exception);
            }
            Trace.TraceError($"ERROR CONTINUE: {exception} ({source}).");
        }

        [NonEvent]
        public void GetTokenStart(object source) {
            if (this.IsEnabled()) {
                this.GetTokenStart(CreateSourceString(source));
            }
        }

        [Event(40255, Level = EventLevel.Informational, Message = "GetToken start. Source: {0}")]
        void GetTokenStart(string source) {
            this.WriteEvent(40255, source);
        }

        [NonEvent]
        public void GetTokenStop(DateTime tokenExpiry) {
            if (this.IsEnabled()) {
                this.GetTokenStop(DateTimeToString(tokenExpiry));
            }
        }

        [Event(40256, Level = EventLevel.Informational, Message = "GetToken stop. New token expires at {0}.")]
        void GetTokenStop(string tokenExpiry) {
            this.WriteEvent(40256, tokenExpiry);
        }


        [NonEvent]
        public ArgumentNullException ArgumentNull(string paramName, object source = null, EventLevel level = EventLevel.Error) {
            return this.Rethrow(new ArgumentNullException(paramName), source, level);
        }

        [NonEvent]
        public ArgumentException Argument(string paramName, string message, object source = null, EventLevel level = EventLevel.Error) {
            return this.Rethrow(new ArgumentException(message, paramName), source, level);
        }

        [NonEvent]
        public ArgumentOutOfRangeException ArgumentOutOfRange(string paramName, object actualValue, string message, object source = null, EventLevel level = EventLevel.Error) {
            return this.Rethrow(new ArgumentOutOfRangeException(paramName, actualValue, message), source, level);
        }

        [NonEvent]
        public TimeoutException Timeout(string message, object source = null, EventLevel level = EventLevel.Error) {
            return this.Rethrow(new TimeoutException(message), source, level);
        }

        [NonEvent]
        public TException Rethrow<TException>(TException exception, object source = null, EventLevel level = EventLevel.Error)
            where TException : Exception {
            // Avoid converting ToString, etc. if ETW tracing is not enabled.
            switch (level) {
                case EventLevel.Critical:
                case EventLevel.LogAlways:
                case EventLevel.Error:
                    this.ThrowingExceptionError(CreateSourceString(source), ExceptionToString(exception));
                    break;
                case EventLevel.Warning:
                    this.ThrowingExceptionWarning(CreateSourceString(source), ExceptionToString(exception));
                    break;
                case EventLevel.Informational:
                case EventLevel.Verbose:
                default:
                    this.ThrowingExceptionInfo(CreateSourceString(source), ExceptionToString(exception));
                    break;
            }

            // This allows "throw ServiceBusEventSource.Log.ThrowingException(..."
            return exception;
        }

        [Event(40262, Level = EventLevel.Error, Message = "{0} Throwing an Exception: {1}")]
        public void ThrowingExceptionError(string source, string exception) {
            if (this.IsEnabled()) {
                this.WriteEvent(40262, source, exception);
            }
        }

        [Event(40263, Level = EventLevel.Warning, Message = "{0} Throwing an Exception: {1}")]
        public void ThrowingExceptionWarning(string source, string exception) {
            if (this.IsEnabled()) {
                this.WriteEvent(40263, source, exception);
            }
        }

        [Event(40264, Level = EventLevel.Informational, Message = "{0} Throwing an Exception: {1}")]
        public void ThrowingExceptionInfo(string source, string exception) {
            if (this.IsEnabled()) {
                this.WriteEvent(40264, source, exception);
            }
        }

        [Event(40265, Level = EventLevel.Verbose , Message = "{0}")]
        public void TraceVerbose(string message) {
            if (this.IsEnabled()) {
                this.WriteEvent(40265, message);
            }
            Trace.WriteLine(message);
        }

        [NonEvent]
        internal static string CreateSourceString(object source) {
            Type type;
            string s;
            if (source == null) {
                return string.Empty;
            }
            else if ((type = source as Type) != null) {
                return type.Name;
            }
            else if ((s = source as string) != null) {
                return s;
            }
            return source.ToString();
        }

        [NonEvent]
        static string ExceptionToString(Exception exception) {
            return exception?.ToString() ?? string.Empty;
        }

        [NonEvent]
        static string DateTimeToString(DateTime dateTime) {
            return dateTime.ToString(CultureInfo.InvariantCulture);
        }
    }
}
