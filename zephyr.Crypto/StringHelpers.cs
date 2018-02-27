using System;
using System.Text;


namespace Zephyr.Crypto
{
    public class StringHelpers
    {
        #region base64
        public static string Base64Encode(string value)
        {
            byte[] valueBytes = ASCIIEncoding.ASCII.GetBytes( value );
            return Convert.ToBase64String( valueBytes );
        }

        public static string Base64EncodeFromBytes(byte[] valueBytes)
        {
            return Convert.ToBase64String( valueBytes );
        }

        public static string Base64Decode(string value)
        {
            byte[] valueBytes = Convert.FromBase64String( value );
            return ASCIIEncoding.ASCII.GetString( valueBytes );
        }

        public static byte[] Base64DecodeToBytes(string value)
        {
            return Convert.FromBase64String( value );
        }

        public static bool TryBase64Decode(string encodedValue, out string decodedValue)
        {
            try
            {
                byte[] valueBytes = Convert.FromBase64String( encodedValue );
                decodedValue = ASCIIEncoding.ASCII.GetString( valueBytes );
                return true;
            }
            catch
            {
                decodedValue = null;
                return false;
            }
        }
        #endregion
    }
}