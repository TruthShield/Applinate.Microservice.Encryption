// Copyright (c) TruthShield, LLC. All rights reserved.
namespace Applinate.Encryption
{
    internal sealed class DoNotEncrypt : IEncrypt
    {
        public string Decrypt(string value, string key) => value;

        public string Encrypt(string value, string key) => value;
    }
}