// Copyright (c) TruthShield, LLC. All rights reserved.
namespace Applinate.Encryption.Tests
{
    using Applinate.Test;
    using FluentAssertions;
    using Xunit;
    using static EncryptionProvider;

    public class EncryptionTests : EncryptionTestBase
    {
        

        [Fact]
        public void EncryptionAndDecryptionWork()
        {
            var value = "secureValue";
            var encrypted = Encrypt(value, Thumbprint);
            var decrypted = Decrypt(encrypted, Thumbprint);

            decrypted.Should().Be(value);
        }
    }

    public class EncryptionTestBase : ApplinateTestBase, IDisposable
    {
        public string Thumbprint { get; }
        public EncryptionTestBase()
        {
            Thumbprint = CertProvider.CreateAndSaveNewCertToStore("");
        }

        public void Dispose()
        {
            CertProvider.DeleteCertFromStore(Thumbprint);
        }
    }


}