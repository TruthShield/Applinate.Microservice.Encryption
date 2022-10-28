namespace Applinate.Encryption.Tests
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Xunit;

    internal static class CertProvider
    {
        internal static string CreateAndSaveNewCertToStore(string testCertName)
        {
            using RSA rsaOther = RSA.Create();
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;

            var request = new CertificateRequest(
                testCertName,
                rsaOther,
                hashAlgorithm,
                RSASignaturePadding.Pkcs1);

            byte[] signature;
            byte[] data = request.SubjectName.RawData;

            DateTimeOffset now = DateTimeOffset.UtcNow;

            using var cert = request.CreateSelfSigned(now, now.AddDays(1));
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                signature = rsa.SignData(data, hashAlgorithm, RSASignaturePadding.Pkcs1);
            }

            // RSAOther is exportable, so ensure PFX export succeeds
            byte[] pfxBytes = cert.Export(X509ContentType.Pkcs12, request.SubjectName.Name);
            Assert.InRange(pfxBytes.Length, 100, int.MaxValue);

            var certToImport = new X509Certificate2(pfxBytes, request.SubjectName.Name);

            using (var store = new X509Store())
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(certToImport);
            }

            return cert.Thumbprint;
        }


        internal static X509Certificate2 GetCertFromStore(string thumbprint)
        {
            using X509Store store = new X509Store();
            store.Open(OpenFlags.ReadOnly);

            var certCollection = store.Certificates;
            var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false); // X509FindType.FindByTimeValid requires local time not UTC
            var signingCert = currentCerts.Find(X509FindType.FindByThumbprint, thumbprint, false);

            return signingCert[0];
        }

        internal static void DeleteCertFromStore(string thumbprint)
        {
            using var store = new X509Store();
            store.Open(OpenFlags.ReadWrite);
            var signingCert = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            store.RemoveRange(signingCert);
        }
    }
}
