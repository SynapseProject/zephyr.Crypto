using NUnit.Framework;
using Zephyr.Crypto;
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace zephyr.Crypto.UnitTests
{
    [TestFixture]
    public class RsaTests
    {
        string _kcn = "sample";
        string _pubPrivFilePath = @"c:\temp\sample.pubPrivKey";
        string _pubOnlyFilePath = @"c:\temp\sample.pubOnlyKey";
        string _badFilePath = @"c:\badFilePath\sample.pubPrivKey";
        string _plainText = "Plain text";
        string _encryptedText = "6nfX01TUfFaliu1wit5RJ5JQNFBzxWSePsviImlPKReIFSjpktWW6RbGk4pNj+fqh2DOWquaMzdXI27YFVuFJQ==";

        [Test]
        [Category("Rsa")]
        public void GenerateRsaKeys_NullAndEmptyInputs()
        {
            Assert.Throws<ArgumentException>(() => RsaHelpers.GenerateRsaKeys((string)null, null, null));
            Assert.Throws<ArgumentException>(() => RsaHelpers.GenerateRsaKeys(string.Empty, string.Empty, string.Empty));
        }
        [Test]
        [Category("Rsa")]
        public void GenerateRsaKeys_FileOnly()
        {
            if (File.Exists(_pubPrivFilePath))
                File.Delete(_pubPrivFilePath);
            if (File.Exists(_pubOnlyFilePath))
                File.Delete(_pubOnlyFilePath);

            RsaHelpers.GenerateRsaKeys((string)null, _pubPrivFilePath, _pubOnlyFilePath);
            Assert.IsTrue(File.Exists(_pubPrivFilePath));
            Assert.IsTrue(File.Exists(_pubOnlyFilePath));
        }
        [Test]
        [Category("Rsa")]
        public void GenerateRsaKeys_FileOnly_BadPath()
        {
            Assert.Throws<DirectoryNotFoundException>(() => RsaHelpers.GenerateRsaKeys((string)null, _badFilePath, null));
            Assert.Throws<DirectoryNotFoundException>(() => RsaHelpers.GenerateRsaKeys((string)null, null, _badFilePath));
        }
        [Test]
        [Category("Rsa")]
        public void GenerateRsaKeys_ContainerAndFile()
        {
            if (File.Exists(_pubPrivFilePath))
                File.Delete(_pubPrivFilePath);
            if (File.Exists(_pubOnlyFilePath))
                File.Delete(_pubOnlyFilePath);

            RsaHelpers.GenerateRsaKeys(_kcn, _pubPrivFilePath, _pubOnlyFilePath);
            Assert.IsTrue(RsaHelpers.KeyContainerExist(_kcn));
            Assert.IsTrue(File.Exists(_pubPrivFilePath));
            Assert.IsTrue(File.Exists(_pubOnlyFilePath));
        }
        [Test]
        [Category("Rsa")]
        public void Encrypt_NullAndEmptyInputs()
        {            
            Assert.Throws<ArgumentException>(() => RsaHelpers.Encrypt());
            Assert.Throws<ArgumentException>(() => RsaHelpers.Encrypt(filePath: _pubOnlyFilePath));
            Assert.Throws<ArgumentException>(() => RsaHelpers.Encrypt(keyContainerName:_kcn));
            Assert.Throws<ArgumentException>(() => RsaHelpers.Encrypt(value:_plainText));
            Assert.Throws<ArgumentException>(() => RsaHelpers.Encrypt(filePath: _pubOnlyFilePath, value:string.Empty));
        }
        [Test]
        [Category("Rsa")]
        public void Encrypt_FromFile_BadFile()
        {
            Assert.Throws<DirectoryNotFoundException>(() => RsaHelpers.Encrypt(filePath:_badFilePath, value: _plainText));
        }
        [Test]
        [Category("Rsa")]
        public void EncryptDecrypt_FromFile()
        {
            RsaHelpers.GenerateRsaKeys(pubPrivFilePath: _pubPrivFilePath, pubOnlyFilePath: _pubOnlyFilePath);
            string _cipherText = RsaHelpers.Encrypt(filePath: _pubOnlyFilePath, value:_plainText);
            Assert.AreEqual(_plainText, RsaHelpers.Decrypt(filePath: _pubPrivFilePath, value: _cipherText));            
        }
        [Test]
        [Category("Rsa")]
        public void EncryptDecrypt_FromContainer()
        {
            RsaHelpers.GenerateRsaKeys(keyContainerName: _kcn);
            string _encryptedText = RsaHelpers.Encrypt(keyContainerName: _kcn, value: _plainText);
            Assert.AreEqual(_plainText, RsaHelpers.Decrypt(keyContainerName: _kcn, value: _encryptedText));
            Assert.Throws<FormatException>(() => RsaHelpers.Decrypt(keyContainerName: _kcn, value: _encryptedText + "x"));
        }
        [Test]
        [Category("Rsa")]
        public void Encrypt_UsingCspFlagsUseExistingKey_InvalidKey()
        {
            Assert.Throws<CryptographicException>(() => RsaHelpers.Encrypt(keyContainerName: "nosuchkeycontainername", flags: CspProviderFlags.UseExistingKey, value: _plainText));
            Assert.Throws<CryptographicException>(() => RsaHelpers.Decrypt(keyContainerName: "nosuchkeycontainername", flags: CspProviderFlags.UseExistingKey, value: _encryptedText));
        }
        [Test]
        [Category("Rsa")]
        public void Decrypt_NullAndEmptyInputs()
        {
            Assert.Throws<ArgumentException>(() => RsaHelpers.Decrypt());
            Assert.Throws<ArgumentException>(() => RsaHelpers.Decrypt(filePath: _pubPrivFilePath));
            Assert.Throws<ArgumentException>(() => RsaHelpers.Decrypt(keyContainerName: _kcn));
            Assert.Throws<ArgumentException>(() => RsaHelpers.Decrypt(value: _encryptedText));            
            Assert.Throws<ArgumentException>(() => RsaHelpers.Decrypt(filePath: _pubOnlyFilePath, value: string.Empty));
        }
        [Test]
        [Category("Rsa")]
        public void Decrypt_withPubOnlyKey()
        {
            RsaHelpers.GenerateRsaKeys(pubOnlyFilePath: _pubOnlyFilePath);
            Assert.Throws<CryptographicException>(() => RsaHelpers.Decrypt(filePath: _pubOnlyFilePath, value: _encryptedText));
        }
        [Test]
        [Category("Rsa")]
        public void Decrypt_BadValue()
        {
            RsaHelpers.GenerateRsaKeys(pubPrivFilePath: _pubPrivFilePath);
            Assert.Throws<FormatException>(() => RsaHelpers.Decrypt(filePath: _pubPrivFilePath, value: _encryptedText+"x"));
        }
    }
}
