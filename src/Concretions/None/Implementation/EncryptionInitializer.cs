// Copyright (c) TruthShield, LLC. All rights reserved.
namespace Applinate.Encryption
{
    using Applinate;
    using Microsoft.Extensions.DependencyInjection;

    internal sealed class EncryptionInitializer : IInitialize
    {
        public bool SkipDuringTesting => false;

        public void Initialize(bool testing = false)
        {
            Applinate.ServiceProvider.Register<IEncrypt>(() => new DoNotEncrypt(), InstanceLifetime.Singleton);
        }
    }
}