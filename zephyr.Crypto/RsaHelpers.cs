using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Zephyr.Crypto
{
    public class RsaHelpers
    {
        #region rsa
        public static void GenerateRsaKeys(string keyContainerName, string pubPrivFilePath, string pubOnlyFilePath)
        {
            CspParameters cspParams = new CspParameters
            {
                KeyContainerName = keyContainerName
            };
            GenerateRsaKeys( cspParams, pubPrivFilePath, pubOnlyFilePath );
        }
        public static void GenerateRsaKeys(CspParameters cspParams, string pubPrivFilePath, string pubOnlyFilePath)
        {
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider( cspParams );

            if( !string.IsNullOrEmpty( pubPrivFilePath ) )
            {
                using( StreamWriter sw = new StreamWriter( pubPrivFilePath ) )
                {
                    sw.Write( rsaKey.ToXmlString( true ) );
                }
            }

            if( !string.IsNullOrEmpty( pubOnlyFilePath ) )
            {
                using( StreamWriter sw = new StreamWriter( pubOnlyFilePath ) )
                {
                    sw.Write( rsaKey.ToXmlString( false ) );
                }
            }
        }

        public static RSACryptoServiceProvider LoadRsaKeys(string keyContainerName, string filePath)
        {
            CspParameters cspParams = new CspParameters
            {
                KeyContainerName = keyContainerName
            };
            return LoadRsaKeys( cspParams, filePath );
        }
        public static RSACryptoServiceProvider LoadRsaKeys(string keyContainerName, string filePath, CspProviderFlags flags)
        {
            CspParameters cspParams = new CspParameters
            {
                KeyContainerName = keyContainerName,
                Flags = flags
            };
            return LoadRsaKeys( cspParams, filePath );
        }
        public static RSACryptoServiceProvider LoadRsaKeys(CspParameters cspParams, string filePath)
        {
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider( cspParams );
            if( File.Exists( filePath ) )
            {
                using( StreamReader sr = new StreamReader( filePath ) )
                {
                    rsaKey.FromXmlString( sr.ReadToEnd() );
                }
                return rsaKey;
            }
            else
            {
                return null;
            }
        }

        public static string Encrypt(string keyContainerName, string filePath, string value)
        {
            return Encrypt( keyContainerName, filePath, CspProviderFlags.NoFlags, value );
        }
        public static string Encrypt(string keyContainerName, string filePath, CspProviderFlags flags, string value)
        {
            RSACryptoServiceProvider rsa = LoadRsaKeys( keyContainerName, filePath, flags );
            return Encrypt( rsa, value );
        }

        public static string Encrypt(RSACryptoServiceProvider rsa, string value)
        {
            byte[] valueBytes = Encoding.ASCII.GetBytes( value );
            byte[] encrypted = rsa.Encrypt( valueBytes, false );
            return Convert.ToBase64String( encrypted );
        }

        public static string Decrypt(string keyContainerName, string filePath, string value)
        {
            return Decrypt( keyContainerName, filePath, CspProviderFlags.NoFlags, value );
        }
        public static string Decrypt(string keyContainerName, string filePath, CspProviderFlags flags, string value)
        {
            RSACryptoServiceProvider rsa = LoadRsaKeys( keyContainerName, filePath, flags );
            return Decrypt( rsa, value );
        }

        public static string Decrypt(RSACryptoServiceProvider rsa, string value)
        {
            byte[] valueBytes = Convert.FromBase64String( value );
            byte[] decrypted = rsa.Decrypt( valueBytes, false );
            return Encoding.ASCII.GetString( decrypted );
        }
        #endregion
    }
}