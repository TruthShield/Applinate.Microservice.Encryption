// Copyright (c) TruthShield, LLC. All rights reserved.
namespace Applinate.Encryption
{
    public static class EncryptionProvider
    {
        public static string DefaultKey => ConfigurationProvider.GetConfiguration<ConfigValues>().CertificateKey;

        /// <summary>
        /// decrypts a string
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string Decrypt(string value, string? key = null) => 
            ServiceProvider.Locate<IEncrypt>().Decrypt(value, key ?? DefaultKey);

        /// <summary>
        /// Encrypts a string
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key">the key.  If not supplied, the system will look for a default key in the configuration</param>
        /// <returns></returns>
        public static string Encrypt(string value, string? key = null) => 
            ServiceProvider.Locate<IEncrypt>()
            .Encrypt(value, key ?? DefaultKey);
    }
}