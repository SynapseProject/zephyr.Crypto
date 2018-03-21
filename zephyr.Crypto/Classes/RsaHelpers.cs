using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Zephyr.Crypto
{
    public class RsaHelpers
    {
        #region rsa
        public static void GenerateRsaKeys(string keyContainerName = null, string pubPrivFilePath = null, string pubOnlyFilePath = null)
        {
            if (string.IsNullOrWhiteSpace(keyContainerName) && string.IsNullOrWhiteSpace(pubPrivFilePath) && string.IsNullOrWhiteSpace(pubOnlyFilePath))
                throw new ArgumentException("Invalid argument");

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

        public static RSACryptoServiceProvider LoadRsaKeys(string keyContainerName = null, string filePath = null, CspProviderFlags flags = CspProviderFlags.NoFlags)
        {
            CspParameters cspParams = new CspParameters
            {
                KeyContainerName = keyContainerName,
                Flags = flags
            };
            
            return LoadRsaKeys(cspParams, !string.IsNullOrWhiteSpace(keyContainerName) ? null : filePath);            
        }

        public static RSACryptoServiceProvider LoadRsaKeys(CspParameters cspParams, string filePath)
        {
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider( cspParams );
            if (string.IsNullOrWhiteSpace(filePath))
                return rsaKey;
            else
            {
                using (StreamReader sr = new StreamReader(filePath))
                {
                    rsaKey.FromXmlString(sr.ReadToEnd());
                }
                return rsaKey;
            }
        }
        
        public static string Encrypt(string keyContainerName = null, string filePath = null, CspProviderFlags flags = CspProviderFlags.NoFlags, string value = null)
        {            
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Invalid argument");

            RSACryptoServiceProvider rsa = null;
            if (!string.IsNullOrWhiteSpace(keyContainerName))   // container name takes precedence over file
                rsa = LoadRsaKeys(keyContainerName: keyContainerName, flags: flags);
            else if (!string.IsNullOrWhiteSpace(filePath))
                rsa = LoadRsaKeys(filePath: filePath, flags: flags);
            else
                throw new ArgumentException("Missing key container name or path to key file.");

            return Encrypt( rsa, value );
        }

        public static string Encrypt(RSACryptoServiceProvider rsa, string value)
        {
            byte[] valueBytes = Encoding.ASCII.GetBytes( value );
            byte[] encrypted = rsa.Encrypt( valueBytes, false );
            return Convert.ToBase64String( encrypted );
        }

        public static string EncryptFromFile(string filePath, string value)
        {
            return Encrypt(filePath: filePath, value: value);
        }

        public static string EncryptFromFile(string filePath, CspProviderFlags flags, string value)
        {
            return Encrypt(filePath: filePath, flags: flags, value: value);
        }

        public static string EncryptFromContainer(string keyContainerName, string value)
        {
            return Encrypt(keyContainerName: keyContainerName, value: value);
        }

        public static string EncryptFromContainer(string keyContainerName, CspProviderFlags flags, string value)
        {
            return Encrypt(keyContainerName: keyContainerName, flags: flags, value: value);
        }

        public static string Decrypt(string keyContainerName = null, string filePath = null, CspProviderFlags flags = CspProviderFlags.NoFlags, string value = null)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Invalid argument");

            RSACryptoServiceProvider rsa = null;
            // container name takes precedence over file
            if (!string.IsNullOrWhiteSpace(keyContainerName))   
                // set the UseExistingKey so that rsacryptoserviceprovider doesnt go and generate new keys
                rsa = LoadRsaKeys(keyContainerName: keyContainerName, flags: flags | CspProviderFlags.UseExistingKey);
            else if (!string.IsNullOrWhiteSpace(filePath))
                rsa = LoadRsaKeys(filePath: filePath, flags: flags);
            else
                throw new ArgumentException("Missing key container name or path to key file.");
            
            return Decrypt( rsa, value );
        }

        public static string Decrypt(RSACryptoServiceProvider rsa, string value)
        {
            byte[] valueBytes = Convert.FromBase64String( value );
            byte[] decrypted = rsa.Decrypt( valueBytes, false );
            return Encoding.ASCII.GetString( decrypted );
        }

        public static string DecryptFromFile(string filePath, string value)
        {
            return Decrypt(filePath: filePath, value: value);
        }

        public static string DecryptFromFile(string filePath, CspProviderFlags flags, string value)
        {
            return Decrypt(filePath: filePath, flags: flags, value: value);
        }

        public static string DecryptFromContainer(string keyContainerName, string value)
        {
            return Decrypt(keyContainerName: keyContainerName, value: value);
        }

        public static string DecryptFromContainer(string keyContainerName, CspProviderFlags flags, string value)
        {
            return Decrypt(keyContainerName: keyContainerName, flags: flags, value: value);
        }

        public static bool KeyContainerExist(string keyContainerName)
        {
            var cspParams = new CspParameters
            {
                Flags = CspProviderFlags.UseExistingKey,
                KeyContainerName = keyContainerName
            };

            try
            {
                new RSACryptoServiceProvider(cspParams);
                return true;
            }
            catch
            {
                return false;
            }

        }
        #endregion
    }
}