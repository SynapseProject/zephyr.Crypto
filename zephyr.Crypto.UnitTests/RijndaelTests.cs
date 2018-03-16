using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using Zephyr.Crypto;

namespace zephyr.Crypto.UnitTests
{
    [TestFixture]
    public class RijndaelTests
    {
        string _plaintext = "Plain text";
        string _passPhrase = "PassPhrase";
        string _saltValue = "SaltValue";
        string _iv = "1234567890123456";    // length must be block size (128) / 8 = 16
        string _encryptedString = "abcd"; //"+OQciPBxg+AH/3NyJwgO+A==";

        [Test]
        [Category("Rijndael")]
        public void Encrypt_NullInputs()
        {
            Assert.Throws<ArgumentNullException>(() => RijndaelHelpers.Encrypt(null, null, null, null));
            Assert.Throws<ArgumentNullException>(() => RijndaelHelpers.Encrypt(_plaintext, null, null, null));
            Assert.Throws<ArgumentNullException>(() => RijndaelHelpers.Encrypt(_plaintext, _passPhrase, null, null));
            Assert.Throws<ArgumentNullException>(() => RijndaelHelpers.Encrypt(_plaintext, _passPhrase, _saltValue, null));
        }
        [Test]
        [Category("Rijndael")]
        public void Encrypt_InvalidIV()
        {
            Assert.Throws<CryptographicException>(() => RijndaelHelpers.Encrypt(_plaintext, _passPhrase, _saltValue, "IV"));
        }
        [Test]
        [Category("Rijndael")]
        public void EncryptDecrypt()
        {            
            string _encryptedText = RijndaelHelpers.Encrypt(_plaintext, _passPhrase, _saltValue, _iv);
            Assert.IsNotEmpty(_encryptedText);
            Assert.AreEqual(_plaintext, RijndaelHelpers.Decrypt(_encryptedText, _passPhrase, _saltValue, _iv));
            // test with non base64 string
            Assert.Throws<FormatException>( () => RijndaelHelpers.Decrypt(_encryptedText+"x", _passPhrase, _saltValue, _iv) );
        }
        [Test]
        [Category("Rijndael")]
        public void Decrypt_NullInputs()
        {
            Assert.Throws<ArgumentNullException>(() => RijndaelHelpers.Decrypt(null, null, null, null));
            Assert.Throws<ArgumentNullException>(() => RijndaelHelpers.Decrypt(_encryptedString, null, null, null));
            Assert.Throws<ArgumentNullException>(() => RijndaelHelpers.Decrypt(_encryptedString, _passPhrase, null, null));
            Assert.Throws<ArgumentNullException>(() => RijndaelHelpers.Decrypt(_encryptedString, _passPhrase, _saltValue, null));
        }
        [Test]
        [Category("Rijndael")]
        public void Decrypt_InvalidCipherText()
        {
            Assert.Throws<FormatException>(() => RijndaelHelpers.Decrypt("abc", "PassPhrase", "SaltValue", "IV"));
        }
        [Test]
        [Category("Rijndael")]
        public void Decrypt_InvalidIV()
        {
            Assert.Throws<CryptographicException>(() => RijndaelHelpers.Decrypt(_encryptedString, _passPhrase, _saltValue, "IV"));
        }        
    }
}
