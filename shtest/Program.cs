using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Zephyr.Crypto;

namespace shtest
{
    class Program
    {
        static void Main(string[] args)
        {
            //var cspParams = new CspParameters
            //{
            //    Flags = CspProviderFlags.UseExistingKey ,                
            //    KeyContainerName = "myKey"
            //};

            //try
            //{
            //    new RSACryptoServiceProvider(cspParams);
            //    Console.WriteLine("yes");

            //}
            //catch 
            //{
            //    Console.WriteLine("no");
            //}

            //string s = RijndaelHelpers.Encrypt("Plain text", "PassPhrase", "SaltValue", "1234567890123456");
            //Console.WriteLine(s);
            //RsaHelpers.GenerateRsaKeys((string)null, null, null);
            //RSACryptoServiceProvider rsa = RsaHelpers.LoadRsaKeys("t", @"c:\temp\sample.pubpriv", CspProviderFlags.UseExistingKey);
            //Console.WriteLine(RsaHelpers.Encrypt(filePath: @"c:\temp\sample.pubpriv", value:null));
            RsaHelpers.Encrypt(keyContainerName: "abc", flags: CspProviderFlags.UseExistingKey, value: "abc");
            //Console.WriteLine(RsaHelpers.Decrypt(filePath: @"c:\temp\sample.pubOnlyKey", value: "6nfX01TUfFaliu1wit5RJ5JQNFBzxWSePsviImlPKReIFSjpktWW6RbGk4pNj+fqh2DOWquaMzdXI27YFVuFJQ=="));
            //Console.WriteLine(rsa.CspKeyContainerInfo.ToString());
            //Console.WriteLine(rsa.CspKeyContainerInfo.KeyContainerName);
            //Console.WriteLine(rsa.PublicOnly);
            Console.ReadLine();
        }
    }
}
