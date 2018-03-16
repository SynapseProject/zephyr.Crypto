using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Zephyr.Crypto;

namespace Zephyr.Crypto.UnitTests
{
    [TestFixture]
    public class EncodingTests
    {
        const string _emptyString = "";
        const string _nullString = null;
        const string _originalString = "It's a secret";
        const string _base64String = "SXQncyBhIHNlY3JldA==";
        const string _nonBase64String = "abc";
        byte[] _emptyByteArray = new byte[0];
        byte[] _nullByteArray = null;
        byte[] _nonEmptyByteArray = new byte[] { 100, 200 };

        [OneTimeSetUp]
        public void Init()
        {
        }

        [Test]
        [Category("Encoding")]
        public void ToBase64_NullString()
        {            
            string _nullString = null;            
            Assert.Throws<ArgumentNullException>(() => EncodingHelpers.ToBase64(_nullString));
        }
        [Test]
        [Category("Encoding")]
        public void ToBase64_NullByteArray()
        {            
            Assert.Throws<ArgumentNullException>(() => EncodingHelpers.ToBase64(_nullByteArray));
        }

        [Test]
        [Category("Encoding")]
        [TestCase(_emptyString)]
        [TestCase(_originalString)]
        public void ToBase64_String(string plainText)
        {
            Assert.AreEqual(plainText, EncodingHelpers.FromBase64(EncodingHelpers.ToBase64(plainText)));
        }
        [Test]
        [Category("Encoding")]
        // [TestCase(new byte[0])] // NUnit wont pass this value to the method
        // [TestCase(new byte[] { 100, 200 })]
        public void ToBase64_EmptyByteArray()
        {
            Assert.AreEqual(_emptyByteArray, EncodingHelpers.FromBase64ToBytes(EncodingHelpers.ToBase64(_emptyByteArray)));
        }
        [Test]
        [Category("Encoding")]
        public void ToBase64_NonEmptyByteArray()
        {
            Assert.AreEqual(_nonEmptyByteArray, EncodingHelpers.FromBase64ToBytes(EncodingHelpers.ToBase64(_nonEmptyByteArray)));
        }
        [Test]
        [Category("Encoding")]
        public void FromBase64_NullString()
        {
            Assert.Throws<ArgumentNullException>(() => EncodingHelpers.FromBase64(_nullString));
        }
        [Test]
        [Category("Encoding")]
        [TestCase(_emptyString)]
        [TestCase(_base64String)]
        public void FromBase64_Base64String(string encodedString)
        {            
            Assert.AreEqual(encodedString, EncodingHelpers.ToBase64(EncodingHelpers.FromBase64(encodedString)));
        }
        [Test]
        [Category("Encoding")]
        public void FromBase64_NonBase64String()
        {
            string _nonBase64String = "abc";
            Assert.Throws<FormatException>(() => EncodingHelpers.ToBase64(EncodingHelpers.FromBase64(_nonBase64String)));
        }
        [Test]
        [Category("Encoding")]
        public void FromBase64ToBytes_NullString()
        {
            string _nullString = null;
            Assert.Throws<ArgumentNullException>(() => EncodingHelpers.FromBase64ToBytes(_nullString));
        }
        [Test]
        [Category("Encoding")]
        [TestCase(_emptyString)]
        [TestCase(_base64String)]
        public void FromBase64ToBytes_Base64String(string encodedString)
        {
            Assert.AreEqual(encodedString, EncodingHelpers.ToBase64(EncodingHelpers.FromBase64ToBytes(encodedString)));
        }
        [Test]
        [Category("Encoding")]
        public void FromBase64ToBytes_NonBase64String()
        {
            string _nonBase64String = "abc";
            Assert.Throws<FormatException>(() => EncodingHelpers.ToBase64(EncodingHelpers.FromBase64(_nonBase64String)));
        }
        [Test]
        [Category("Encoding")]
        public void TryBase64Decode_NullString()
        {
            string _nullString = null;
            Assert.IsFalse(EncodingHelpers.TryBase64Decode(_nullString, out string decodedValue));
        }
        [Test]
        [Category("Encoding")]
        [TestCase(_emptyString)]
        [TestCase(_base64String)]
        public void TryBase64Decode_Base64String(string encodedString)
        {
            Assert.IsTrue(EncodingHelpers.TryBase64Decode(encodedString, out string decodedValue));
        }
        [Test]
        [Category("Encoding")]
        public void TryBase64Decode_NonBase64String()
        {
            Assert.IsFalse(EncodingHelpers.TryBase64Decode(_nonBase64String, out string decodedValue));
        }
    }

}
