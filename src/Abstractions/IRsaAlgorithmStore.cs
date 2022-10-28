namespace Applinate.Encryption
{
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public interface IRsaAlgorithmStore
    {
        RSA GetAlgorithmByKey(string thumbprint);
    }
}