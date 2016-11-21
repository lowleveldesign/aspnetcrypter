using System;
using System.Security.Cryptography;
using System.Web.Security.Cryptography;

namespace LowLevelDesign.AspNetCrypter
{
    internal sealed class AspNetDecryptor
    {
        private readonly CryptographicKey decryptionKey;
        private readonly CryptographicKey validationKey;

        public AspNetDecryptor(Purpose purpose, CryptographicKey decryptionKey, CryptographicKey validationKey)
        {
            this.decryptionKey = SP800_108.DeriveKey(decryptionKey, purpose);
            this.validationKey = SP800_108.DeriveKey(validationKey, purpose);
        }

        public byte[] DecryptData(byte[] data)
        {
            var cryptoService = new NetFXCryptoService(new GuessCryptoAlgorithmFactory(decryptionKey.KeyLength, 
                validationKey.KeyLength), decryptionKey, validationKey);
            return cryptoService.Unprotect(data);
        }

        private class GuessCryptoAlgorithmFactory : ICryptoAlgorithmFactory
        {
            private readonly SymmetricAlgorithm decryptionAlgorithm;
            private readonly KeyedHashAlgorithm validationAlgorigthm;

            public GuessCryptoAlgorithmFactory(int symmetricKeyLength, int validationKeyLength)
            {
                switch (symmetricKeyLength) {
                    case 64:
                        decryptionAlgorithm = DES.Create();
                        break;
                    case 192:
                        decryptionAlgorithm = TripleDES.Create();
                        break;
                    case 128:
                    case 256:
                        decryptionAlgorithm = Aes.Create();
                        break;
                    default:
                        throw new ArgumentException("Encryption algorithm could not be recognized.");
                }

                switch (validationKeyLength) {
                    case 128:
                        validationAlgorigthm = HMACMD5.Create();
                        break;
                    case 160:
                        validationAlgorigthm = HMACSHA1.Create();
                        break;
                    case 256:
                        validationAlgorigthm = HMACSHA256.Create();
                        break;
                    case 384:
                        validationAlgorigthm = HMACSHA384.Create();
                        break;
                    case 512:
                        validationAlgorigthm = HMACSHA512.Create();
                        break;
                    default:
                        throw new ArgumentException("Validation algorithm could not be recognized.");
                }
            }

            public SymmetricAlgorithm GetEncryptionAlgorithm()
            {
                return decryptionAlgorithm;
            }

            public KeyedHashAlgorithm GetValidationAlgorithm()
            {
                return validationAlgorigthm;
            }
        }
    }
}
