// Copyright (c) TruthShield, LLC. All rights reserved.
using System.Security.Cryptography;
using System.Text;

using static Applinate.Encryption.RsaAlgorithmStoreHelper;

namespace Applinate.Encryption
{
    /// <summary>
    /// Encrypts a string using <see cref="RSA"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// string encrypted with this transform may be decrypted
    /// by with the same RSA private key (generally with a shared
    /// X509 certificate).
    /// </para>
    /// <para>
    /// The given string is encrypted using a random AES256 key.  This key is
    /// then encrypted using RSA, and the RSA public key is sent in plain text
    /// so that when decoding the class knows which RSA key to use.
    /// </para>
    /// </remarks>
    internal class RsaEncrypt : IEncrypt
    {
        public string Decrypt(string value, string key)
        {
            var encryptedBytes   = Convert.FromBase64CharArray(value.ToCharArray(), 0, value.Length);
            var unencryptedBytes = Decode(key, encryptedBytes);
            var compressedResult = Encoding.UTF8.GetString(unencryptedBytes);
            var result           = CompressionProvider.Decompress(compressedResult);

            return result;
        }

        public string Encrypt(string value, string key)
        {
            var compressedValue  = CompressionProvider.Compress(value);
            var unencryptedBytes = Encoding.UTF8.GetBytes(compressedValue);
            var encryptedBytes   = Encode(key, unencryptedBytes);
            var result           = Convert.ToBase64String(encryptedBytes);

            return result;
        }

        private static Aes BuildAes()
        {
            var aes = Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();
            return aes;
        }

        private static ICryptoTransform BuildDecryptor(
            byte[] decryptedKeyAndIV,
            Aes aes,
            byte[] decryptionKey)
        {
            var decryptionIV = new byte[decryptedKeyAndIV.Length - decryptionKey.Length];

            // Copy key into a separate buffer along with the remaining IV bytes.
            Array.Copy(decryptedKeyAndIV, decryptionKey, decryptionKey.Length);
            Array.Copy(decryptedKeyAndIV, decryptionKey.Length, decryptionIV, 0, decryptionIV.Length);
            ICryptoTransform decryptor = aes.CreateDecryptor(decryptionKey, decryptionIV);
            return decryptor;
        }

        private static byte[] Combine(byte[] encryptedData, byte[] rsaHash, byte[] encryptedKeyAndIV)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write(rsaHash);
            bw.Write(encryptedKeyAndIV.Length);
            bw.Write(encryptedKeyAndIV);
            bw.Write(encryptedData.Length);
            bw.Write(encryptedData);
            bw.Flush();

            return ms.ToArray();
        }

        /// <summary>
        /// Decrypts data using the provided RSA key(s) to decrypt an AES key, which decrypts the cookie.
        /// </summary>
        /// <param name="encoded">The encoded data</param>
        /// <returns>The decoded data</returns>
        /// <exception cref="ArgumentNullException">The argument 'encoded' is null.</exception>
        /// <exception cref="ArgumentException">The argument 'encoded' contains zero bytes.</exception>
        /// <exception cref="NotSupportedException">The platform does not support the requested algorithm.</exception>
        /// <exception cref="InvalidOperationException">There are no decryption keys or none of the keys match.</exception>
        private static byte[] Decode(string key, byte[] encoded)
        {
            //
            // NOTE: Produces an encrypted stream as follows:
            //
            // Hashsha?( RSA.Tostring( false ) ) +
            // Length( EncryptRSA( Key + IV )    +
            // EncryptRSA( Key + IV )            +
            // Length( EncryptAES( Data )        +
            // EncryptAES( Data )

            Assert.IsNotNullOrEmpty(encoded, nameof(encoded));
            Assert.IsNotNull(key, nameof(key));

            var rsa = GetAlgorithmByKey(key);
            using var hash = SHA512.Create();
            var hashBytes = hash.HashSize / 8;
            using var reader = new BinaryReader(new MemoryStream(encoded));
            var rsaHash = reader.ReadBytes(hashBytes);
            var encryptedKeyAndIVSize = GetEncryptedKeyAndIVSize(reader);
            var encryptedKeyAndIV = reader.ReadBytes(encryptedKeyAndIVSize);
            var encryptedDataSize = GetEncryptedDataSize(reader, encoded.Length);
            var encryptedData = reader.ReadBytes(encryptedDataSize);
            var decryptedKeyAndIV = rsa.Decrypt(encryptedKeyAndIV, RSAEncryptionPadding.OaepSHA512);
            using var aes = Aes.Create();
            var decryptionKey = new byte[aes.KeySize / 8];

            //
            // Ensure there is sufficient length in the decrypted key and IV buffer for an IV.
            //
            if (decryptedKeyAndIV.Length < decryptionKey.Length)
            {
                //throw DiagnosticUtility.ThrowHelperInvalidOperation(SR.Getstring(SR.ID6047, decryptedKeyAndIV.Length, decryptionKey.Length));
            }

            var decryptor = BuildDecryptor(decryptedKeyAndIV, aes, decryptionKey);
            var result = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);

            return result;
        }

        /// <summary>
        /// Encode the data.  The data is encrypted using the default encryption algorithm (AES-256),
        /// then the AES key is encrypted using RSA and the RSA public key is appended.
        /// </summary>
        /// <param name="data">The data to encode</param>
        /// <exception cref="ArgumentNullException">The argument 'value' is null.</exception>
        /// <exception cref="ArgumentException">The argument 'value' contains zero bytes.</exception>
        /// <exception cref="InvalidOperationException">The EncryptionKey is null.</exception>
        /// <returns>Encoded data</returns>
        private static byte[] Encode(string key, byte[] data)
        {
            //
            // NOTE: Produces an encrypted stream as follows:
            //
            // Hashsha?( RSA.Tostring( false ) ) +
            // Length( EncryptRSA( Key + IV )    +
            // EncryptRSA( Key + IV )            +
            // Length( EncryptAES( Data )        +
            // EncryptAES( Data )

            Assert.IsNotNullOrEmpty(data, nameof(data));
            Assert.IsNotNull(key, nameof(key));

            var rsa = GetAlgorithmByKey(key);
            var aes = BuildAes();
            var encryptedData = EncryptData(data, aes);
            var rsaHash = SHA512.Create().ComputeHash(Encoding.UTF8.GetBytes(rsa.ToXmlString(false)));
            var encryptedKeyAndIV = GetEncryptedKeyAndIV(rsa, aes);

            return Combine(encryptedData, rsaHash, encryptedKeyAndIV);
        }

        private static byte[] EncryptData(byte[] data, Aes aes)
        {
            using var encryptor = aes.CreateEncryptor();
            var encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);

            //RSACryptoServiceProvider provider = rsa as RSACryptoServiceProvider;

            //if (provider == null)
            //{
            //    //throw DiagnosticUtility.ThrowHelperInvalidOperation(SR.Getstring(SR.ID6041));
            //}

            //
            // Concatenate the Key and IV in an attempt to avoid two minimum block lengths in the string
            //

            return encryptedData;
        }

        private static int GetEncryptedDataSize(BinaryReader br, int maxLength)
        {
            int encryptedDataSize = br.ReadInt32();

            if (encryptedDataSize < 0)
            {
                //throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new FormatException(SR.Getstring(SR.ID1008, encryptedDataSize)));
            }

            //
            // Enforce upper limit on data size to prevent large buffer allocation in br.ReadBytes()
            //
            if (encryptedDataSize > maxLength)
            {
                //throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new FormatException(SR.Getstring(SR.ID1009)));
            }

            return encryptedDataSize;
        }

        private static byte[] GetEncryptedKeyAndIV(RSA rsa, Aes aes)
        {
            var keyAndIV = new byte[aes.Key.Length + aes.IV.Length];

            Array.Copy(aes.Key, keyAndIV, aes.Key.Length);
            Array.Copy(aes.IV, 0, keyAndIV, aes.Key.Length, aes.IV.Length);

            byte[] encryptedKeyAndIV = rsa.Encrypt(keyAndIV, RSAEncryptionPadding.OaepSHA512);
            return encryptedKeyAndIV;
        }

        private static int GetEncryptedKeyAndIVSize(BinaryReader br)
        {
            int encryptedKeyAndIVSize = br.ReadInt32();

            if (encryptedKeyAndIVSize < 0)
            {
                //throw new ArgumentException()
                //throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new FormatException(SR.Getstring(SR.ID1006, encryptedKeyAndIVSize)));
            }

            return encryptedKeyAndIVSize;
        }
    }
}