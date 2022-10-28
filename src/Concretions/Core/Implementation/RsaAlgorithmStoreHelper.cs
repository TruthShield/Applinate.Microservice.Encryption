// Copyright (c) TruthShield, LLC. All rights reserved.
using System.Security.Cryptography;

namespace Applinate.Encryption
{
    internal static class RsaAlgorithmStoreHelper
    {
        private static IRsaAlgorithmStore _Store = ServiceProvider.Locate<IRsaAlgorithmStore>(new RsaAlgorithmStore()); 

        internal static RSA GetAlgorithmByKey(string thumbprint) => _Store.GetAlgorithmByKey(thumbprint);
    }
}