using System;
using System.Text;


namespace Zephyr.Crypto
{
    public class EncodingHelpers
    {
        #region base64
        public static string ToBase64(string value)
        {
            byte[] valueBytes = Encoding.ASCII.GetBytes( value );
            return Convert.ToBase64String( valueBytes );
        }

        public static string ToBase64(byte[] valueBytes)
        {
            return Convert.ToBase64String( valueBytes );
        }

        public static string FromBase64(string value)
        {
            byte[] valueBytes = Convert.FromBase64String( value );
            return Encoding.ASCII.GetString( valueBytes );
        }

        public static byte[] FromBase64ToBytes(string value)
        {
            return Convert.FromBase64String( value );
        }

        public static bool TryBase64Decode(string encodedValue, out string decodedValue)
        {
            try
            {
                byte[] valueBytes = Convert.FromBase64String( encodedValue );
                decodedValue = Encoding.ASCII.GetString( valueBytes );
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