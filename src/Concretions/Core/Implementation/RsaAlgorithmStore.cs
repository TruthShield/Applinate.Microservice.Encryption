// Copyright (c) TruthShield, LLC. All rights reserved.
using Polly;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Applinate.Encryption
{
    internal class RsaAlgorithmStore:IRsaAlgorithmStore
    {
        //private static readonly Policy _p = Policy.Handle<Exception>().WaitAndRetry(5, i => TimeSpan.FromMilliseconds(100 * i));


        public RSA GetAlgorithmByKey(string thumbprint) =>
            GetCertificateFromStore(thumbprint).GetRSAPrivateKey() ??
            throw new KeyNotFoundException(thumbprint);
        

        private static  X509Certificate2 GetCertificateFromStore(string thumbprint)
        {
            // Get the certificate store.
            using X509Store store = new X509Store();
            store.Open(OpenFlags.ReadOnly);

            var certCollection = store.Certificates;
            var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);  // NOTE: X509FindType.FindByTimeValid requires local time not UTC
            var signingCert = currentCerts.Find(X509FindType.FindByThumbprint, thumbprint, false);

            if (signingCert.Count == 0)
            {
                throw new InvalidOperationException($"No valid X509 certificate exists in the certificate store with the thumbprint: {thumbprint}");
            }

            if (signingCert.Count > 1)
            {
                throw new InvalidOperationException($"More than one X509 certificate exists in the store with the thumbprint: {thumbprint}");
            }

            return signingCert[0];
        }

    }
}