namespace Applinate.Encryption
{
    public interface IEncrypt
    {
        /// <summary>
        /// Encrypts a string
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key">the encryption key.  If not supplied, the system will look for a default key in the configuration</param>
        /// <returns></returns>
        string Encrypt(string value, string key);

        /// <summary>
        /// decrypts a string
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        string Decrypt(string value, string key);
    }
}