// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.Devices.Proxy {

    /// <summary>
    /// Container class for port scan result infos
    /// </summary>
    public class NetworkScanResult : Poco<NetworkScanResult> {

        /// <summary>
        /// Addresses for this host
        /// </summary>
        public SocketAddress Result {
            get; private set;
        }

        /// <summary>
        /// Name for this host
        /// </summary>
        public string Name {
            get; private set;
        }

        /// <summary>
        /// Proxy on which this record is valid.
        /// </summary>
        public SocketAddress Interface {
            get; private set;
        }

        /// <summary>
        /// Create entry
        /// </summary>
        /// <param name="result"></param>
        /// <param name="interface"></param>
        /// <returns></returns>
        internal static NetworkScanResult Create(
            SocketAddress result, string name, SocketAddress @interface) {
            var entry = Get();
            entry.Result = result;
            entry.Name = name;
            entry.Interface = @interface;
            return entry;
        }

        public override bool IsEqual(NetworkScanResult that) {
            return
                IsEqual(Result, that.Result) &&
                IsEqual(Name, that.Name) &&
                IsEqual(Interface, that.Interface);
        }

        protected override void SetHashCode() {
            MixToHash(Result);
            MixToHash(Name);
            MixToHash(Interface);
        }

        /// <summary>
        /// Return object as string
        /// </summary>
        /// <returns></returns>
        public override string ToString() => $"{Result} ({Name}) on {Interface}";
    }
}