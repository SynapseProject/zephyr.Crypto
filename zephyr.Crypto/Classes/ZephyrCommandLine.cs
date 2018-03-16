using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Linq;
using System.Text;
using Zephyr.Crypto;
using System.Security.Cryptography;

public class ZephyrCommandLine
{
    public void Main(string[] args)
    {
        Arguments a = null;
        try
        {
            a = new Arguments(args);

            if (!a.IsParsed)
                WriteHelpAndExit(a.Message);

            switch (a.Algorithm)
            {
                case AlgorithmType.Base64:
                    if (a.Action == ActionType.Decode)
                        Base64Decode(a.Data, a.ShowActionHelp);
                    else if (a.Action == ActionType.Encode)
                        Base64Encode(a.Data, a.ShowActionHelp);

                    break;

                case AlgorithmType.Rijndael:
                    if (a.Action == ActionType.Encrypt)
                        RijndaelEncrypt(a.Data, a.PassPhrase, a.SaltValue, a.InitializationVector, a.ShowActionHelp);
                    else if (a.Action == ActionType.Decrypt)
                        RijndaelDecrypt(a.Data, a.PassPhrase, a.SaltValue, a.InitializationVector, a.ShowActionHelp);

                    break;

                case AlgorithmType.Rsa:
                    if (a.Action == ActionType.Encrypt)
                        RsaEncrypt(a.Data, a.KeyContainerName, a.KeyFile, a.Flags, a.ShowActionHelp);
                    else if (a.Action == ActionType.Decrypt)
                        RsaDecrypt(a.Data, a.KeyContainerName, a.KeyFile, a.Flags, a.ShowActionHelp);
                    else if (a.Action == ActionType.GenKey)
                        RsaGenKey(a.KeyContainerName, a.KeyFile, a.ShowActionHelp);

                    break;
            }
        }
        catch (Exception ex)
        {
            WriteHelpAndExit(UnwindException(ex));
        }
    }

    static void Base64Decode(string data, bool showHelp)
    {
        if (showHelp)
        {
            List<Parameter> parms = new List<Parameter>
                {
                    new Parameter{ Key= "data", Type = typeof(string), HelpText = "Text to decode"}
                };
            ConsoleColor defaultColor = Console.ForegroundColor;
            Console_WriteLine($"Parameter options for base64 decode:\r\n", ConsoleColor.Green);
            WriteMethodParametersHelp(parms);
            Console.ForegroundColor = defaultColor;
        }
        else
        {
            Console.WriteLine($"Decoding base64 data to string.\r\n");
            Console.WriteLine(EncodingHelpers.FromBase64(data));
        }
    }
    static void Base64Encode(string data, bool showHelp)
    {
        if (showHelp)
        {
            List<Parameter> parms = new List<Parameter>
                {
                    new Parameter{ Key= "data", Type = typeof(string), HelpText = "Text to encode"}
                };
            ConsoleColor defaultColor = Console.ForegroundColor;
            Console_WriteLine($"Parameter options for base64 encode:\r\n", ConsoleColor.Green);
            WriteMethodParametersHelp(parms);
            Console.ForegroundColor = defaultColor;
        }
        else
        {
            Console.WriteLine($"Encoding data to base64.\r\n");
            Console.WriteLine(EncodingHelpers.ToBase64(data));
        }
    }

    static void RijndaelEncrypt(string data, string passPhrase, string saltValue, string initializationValue, bool showHelp)
    {
        if (showHelp)
        {
            List<Parameter> parms = new List<Parameter>
                {
                    new Parameter{ Key= "data", Type = typeof(string), HelpText = "Text to encrypt"},
                    new Parameter{ Key = "pass", Type = typeof(string), HelpText = "Pass phrase"},
                    new Parameter{ Key = "salt", Type = typeof(string), HelpText = "Salt value"},
                    new Parameter{ Key = "iv", Type = typeof(string), HelpText = "Initialization vector"}
                };
            ConsoleColor defaultColor = Console.ForegroundColor;
            Console_WriteLine($"Parameter options for Rijndael encrypt:\r\n", ConsoleColor.Green);            
            WriteMethodParametersHelp(parms);
            Console.ForegroundColor = defaultColor;
        }
        else
        {
            Console.WriteLine("Encrypting data using Rijndael algorithm.\r\n");
            Console.WriteLine(RijndaelHelpers.Encrypt(data, passPhrase, saltValue, initializationValue));
        }
    }

    static void RijndaelDecrypt(string data, string passPhrase, string saltValue, string initializationValue, bool showHelp)
    {
        if (showHelp)
        {
            List<Parameter> parms = new List<Parameter>
                {
                    new Parameter{ Key= "data", Type = typeof(string), HelpText = "Text to decrypt"},
                    new Parameter{ Key = "pass", Type = typeof(string), HelpText = "Pass phrase"},
                    new Parameter{ Key = "salt", Type = typeof(string), HelpText = "Salt value"},
                    new Parameter{ Key = "iv", Type = typeof(string), HelpText = "Initialization vector"}
                };
            ConsoleColor defaultColor = Console.ForegroundColor;
            Console_WriteLine($"Parameter options for Rijndael decrypt:\r\n", ConsoleColor.Green);
            WriteMethodParametersHelp(parms);
            Console.ForegroundColor = defaultColor;
        }
        else
        {
            Console.WriteLine("Decrypting data using Rijndael algorithm.\r\n");
            Console.WriteLine(RijndaelHelpers.Decrypt(data, passPhrase, saltValue, initializationValue));
        }
    }

    static void RsaEncrypt(string data, string keyContainerName, string keyFilePath, CspProviderFlags flags, bool showHelp)
    {
        if (showHelp)
        {
            List<Parameter> parms = new List<Parameter>
                {
                    new Parameter{ Key = "data", Type = typeof(string), HelpText = "Text to encrypt"},
                    new Parameter{ Key = "[kcn]", Type = typeof(string), HelpText = "Key container name"},
                    new Parameter{ Key = "[keyFile]", Type = typeof(string), HelpText = "Path to key file"}
                };
            ConsoleColor defaultColor = Console.ForegroundColor;
            Console_WriteLine($"Parameter options for Rsa encrypt:\r\n", ConsoleColor.Green);
            WriteMethodParametersHelp(parms);
            Console.WriteLine("\r\nNote:");
            Console.WriteLine("Specify either key container name or path to key file.");
            Console.ForegroundColor = defaultColor;
        }
        else
        {
            Console.WriteLine("Encrypting data using Rsa algorithm.\r\n");
            Console.WriteLine(RsaHelpers.Encrypt(keyContainerName: keyContainerName, filePath: keyFilePath, flags: flags, value: data));
        }
    }

    static void RsaDecrypt(string data, string keyContainerName, string keyFilePath, CspProviderFlags flags, bool showHelp)
    {
        if (showHelp)
        {
            List<Parameter> parms = new List<Parameter>
                {
                    new Parameter{ Key = "data", Type = typeof(string), HelpText = "Text to decrypt"},
                    new Parameter{ Key = "[kcn]", Type = typeof(string), HelpText = "Key container name"},
                    new Parameter{ Key = "[keyFile]", Type = typeof(string), HelpText = "Path to key file"}
                };
            ConsoleColor defaultColor = Console.ForegroundColor;
            Console_WriteLine($"Parameter options for Rsa decrypt:\r\n", ConsoleColor.Green);
            WriteMethodParametersHelp(parms);
            Console.WriteLine("\r\nNote:");
            Console.WriteLine("Specify either key container name or path to key file.");
            Console.ForegroundColor = defaultColor;
        }
        else
        {
            Console.WriteLine("Decrypting data using Rsa algorithm.\r\n");
            Console.WriteLine(RsaHelpers.Decrypt(keyContainerName: keyContainerName, filePath: keyFilePath, flags: flags, value: data));
        }
    }
    static void RsaGenKey(string keyContainerName, string keyFile, bool showHelp)
    {
        if (showHelp)
        {
            List<Parameter> parms = new List<Parameter>
                {
                    new Parameter{ Key= "[kcn]", Type = typeof(string), HelpText = "Key container name"},
                    new Parameter{ Key= "[keyFile]", Type = typeof(string), HelpText = "Path to key files"}
                };
            ConsoleColor defaultColor = Console.ForegroundColor;
            Console_WriteLine($"Parameter options for Rsa genkey:\r\n", ConsoleColor.Green);
            WriteMethodParametersHelp(parms);
            Console.WriteLine("\r\nNote:");
            Console.WriteLine("Specify either key container name or path to key files.\r\n");
            Console.WriteLine("If keyFile is specified, action will create the following 2 files:");
            Console.WriteLine("1. {keyFile}.pubPriv (public and private key)");
            Console.WriteLine("2. {keyFile}.pubOnly (public key only)");
            Console.ForegroundColor = defaultColor;
        }
        else
        {
            Console.WriteLine("Generating Rsa key pair.\r\n");
            if (string.IsNullOrWhiteSpace(keyFile))
                RsaHelpers.GenerateRsaKeys(keyContainerName);
            else
                RsaHelpers.GenerateRsaKeys(keyContainerName, $"{keyFile}.pubPriv", $"{keyFile}.pubOnly");
            
            if (!string.IsNullOrWhiteSpace(keyContainerName))
            {
                Console.WriteLine($"Created public/private keypair in user profile key store.");
            }
            if (!string.IsNullOrWhiteSpace(keyFile))
            {
                Console.WriteLine($"Created public/private keypair in [{keyFile}.pubPriv].");
                Console.WriteLine($"Created public key (only) in [{keyFile}.pubOnly].");
            }
        }
    }

    #region Help
    static void WriteMethodParametersHelp(List<Parameter> parms, string prefix = null)
    {
        if (parms.Count == 0)
            Console.WriteLine($"\tNo additional parameter options.");
        else
        {
            foreach (Parameter p in parms)
            {
                //Console.WriteLine("\t{0,-30}{1}", p.Key, GetTypeFriendlyName(p.Type, prefix));
                Console.WriteLine($"    {p.Key,-20} {GetTypeFriendlyName(p.Type, prefix),-20} {p.HelpText}");
            }
        }
    }

    static string GetTypeFriendlyName(Type type, string prefix)
    {
        string typeName = type.ToString().ToLower();
        if (typeName.Contains("guid"))
        {
            if (typeName.Contains("generic.list"))
                return "Csv list of Guids or JSON list of Guids";
            else
                return "Guid";
        }
        else if (typeName.Contains("int"))
        {
            return "int";
        }
        else if (typeName.Contains("bool"))
        {
            return "bool";
        }
        else if (typeName.Contains("string"))
        {
            return "string";
        }
        else if (typeName.Contains("datetime"))
        {
            return "DateTime";
        }
        else if (type.IsEnum)
        {
            return GetEnumValuesCsv(type);
        }
        else
        {
            return type.ToString().Replace(prefix, "");
        }
    }

    static string GetEnumValuesCsv(Type enumType)
    {
        Array values = Enum.GetValues(enumType);
        List<object> av = new List<object>();
        foreach (object v in values) av.Add(v);
        return string.Join(",", av);
    }
    static void WriteHelpAndExit(string message)
    {
        bool haveError = !string.IsNullOrWhiteSpace(message);

        ConsoleColor defaultColor = Console.ForegroundColor;

        Console_WriteLine($"{typeof(ZephyrCommandLine).Assembly.GetName().Name}.dll, Version: {typeof(ZephyrCommandLine).Assembly.GetName().Version}\r\n", ConsoleColor.Green);
        Console.WriteLine("Syntax:");
        Console_WriteLine("  zephyr crypto {0}algorithm{1} {0}action{1} {0}parameters{1}\r\n", ConsoleColor.Cyan, "{", "}");
        Console_WriteLine($"{"  algorithm:",-15}base64|rijndael|rsa\r\n", ConsoleColor.Green);
        Console.WriteLine("  action:");
        Console.WriteLine($"{"    base64",-15}{"encode",-15}Returns base64 encoded value");
        Console.WriteLine($"{"",-15}{"decode",-15}Returns base64 decoded value\r\n");
        Console.WriteLine($"{"    rijndael",-15}{"encrypt",-15}Returns rijndael encrypted value");
        Console.WriteLine($"{"",-15}{"decrypt",-15}Returns rijndael decrypted value\r\n");
        Console.WriteLine($"{"    rsa",-15}{"encrypt",-15}Returns rsa encrypted value");
        Console.WriteLine($"{"",-15}{"decrypt",-15}Returns rsa decrypted value");
        Console.WriteLine($"{"",-15}{"genkey",-15}Creates rsa keypair for use in encrypt/decrypt");
        Console.WriteLine($"{"",-15}{"",-15}actions\r\n");
        Console.WriteLine($"{"  parameters:",-15}List of key:value pair");        
        Console.WriteLine($"{"  ",-15}Type 'help' in the place of parameters for help on parameters");

        if (haveError)
            Console_WriteLine($"\r\n\r\n*** Last error:\r\n{message}\r\n", ConsoleColor.Red);

        Console.ForegroundColor = defaultColor;

        Environment.Exit(haveError ? 1 : 0);
    }

    static void Console_WriteLine(string s, ConsoleColor color, params object[] args)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(s, args);
    }

    // copied from Synapse.Core.Utilities.ExceptionHelpers
    static string UnwindException(Exception ex)
    {
        return UnwindException(null, ex);
    }

    static string UnwindException(string context, Exception ex, bool asSingleLine = false)
    {
        //string lineEnd = asSingleLine ? "|" : @"\r\n";
        string lineEnd = asSingleLine ? "|" : "\r\n";

        StringBuilder msg = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(context))
            msg.Append($"An error occurred in: {context}{lineEnd}");

        msg.Append($"{ex.Message}{lineEnd}");

        if (ex.InnerException != null)
        {
            if (ex.InnerException is AggregateException)
            {
                AggregateException ae = ex.InnerException as AggregateException;
                foreach (Exception wcx in ae.InnerExceptions)
                {
                    Stack<Exception> exceptions = new Stack<Exception>();
                    exceptions.Push(wcx);

                    while (exceptions.Count > 0)
                    {
                        Exception e = exceptions.Pop();

                        if (e.InnerException != null)
                            exceptions.Push(e.InnerException);

                        msg.Append($"{e.Message}{lineEnd}");
                    }
                }
            }
            else
            {
                Stack<Exception> exceptions = new Stack<Exception>();
                exceptions.Push(ex.InnerException);

                while (exceptions.Count > 0)
                {
                    Exception e = exceptions.Pop();

                    if (e.InnerException != null)
                        exceptions.Push(e.InnerException);

                    msg.Append($"{e.Message}{lineEnd}");
                }
            }
        }

        return asSingleLine ? msg.ToString().TrimEnd('|') : msg.ToString();
    }
    #endregion
}
internal class Arguments
{
    public bool IsParsed { get; internal set; }
    public string Message { get; internal set; }
    public bool ShowActionHelp { get; internal set; }

    public AlgorithmType Algorithm { get; internal set; }
    public ActionType Action { get; internal set; }
    public Dictionary<string, string> Parms { get; internal set; }

    public string Data { get; internal set; }
    public string PassPhrase { get; internal set; }
    public string SaltValue { get; internal set; }
    public string InitializationVector { get; internal set; }
    public string KeyFile { get; internal set; }
    public string KeyContainerName { get; internal set; }
    public CspProviderFlags Flags { get; internal set; }

    const string __data = "data";
    const string __passphrase = "pass";
    const string __saltvalue = "salt";
    const string __initializationvector = "iv";
    const string __keyfile = "keyfile";
    const string __keycontainername = "kcn";
    const string __flags = "flags";

    Dictionary<AlgorithmType, List<ActionType>> __actions = new Dictionary<AlgorithmType, List<ActionType>>()
    {
        [AlgorithmType.Base64] = new List<ActionType> { ActionType.Encode, ActionType.Decode },
        [AlgorithmType.Rijndael] = new List<ActionType> { ActionType.Encrypt, ActionType.Decrypt },
        [AlgorithmType.Rsa] = new List<ActionType> { ActionType.Encrypt, ActionType.Decrypt, ActionType.GenKey }
    };

    public Arguments(string[] args)
    {
        IsParsed = false;
        ShowActionHelp = false;

        if (args.Length == 0 || IsHelp(args[0]))
            return;

        #region Algorithm
        if (Enum.TryParse<AlgorithmType>(args[0], true, out AlgorithmType a))
        {
            Algorithm = a;
            if (Algorithm == AlgorithmType.None)
            {
                Message += "  * Not a valid algorithm.\r\n";
                return;
            }
        }
        else
        {
            Message += "  * Unknown algorithm.\r\n";
            return;
        }
        #endregion

        #region Action
        if (args.Length < 2)
        {
            Message += "  * Action not specified.\r\n";
            return;
        }
        if (IsHelp(args[1]))
        {
            return;
        }
        if (Enum.TryParse<ActionType>(args[1], true, out ActionType ac))
        {                        
            if (!__actions[Algorithm].Contains(ac))
            {
                Message += "  * Not a valid Action for Algorithm.\r\n";
                return;
            }
            Action = ac;
        }
        else
        {
            Message += "  * Unknown Action.\r\n";
            return;
        }
        #endregion

        #region Parameters
        if (args.Length > 2 && IsHelp(args[2]))
        {
            ShowActionHelp = true;
            IsParsed = true;
            return;
        }

        // at this stage there shouldn't be any invalid Algorithm and Action

        bool error = false;
        Parms = ParseCmdLine(args, 2, ref error);
        if (error)
            return;
        
        switch (Algorithm)
        {
            case AlgorithmType.Base64:
                if (!GetBase64Parameters())
                    return;                                        

                break;

            case AlgorithmType.Rijndael:
                if (!GetRijndaelParameters())
                    return;

                break;

            case AlgorithmType.Rsa:
                if (Action == ActionType.GenKey)
                {
                    if (!GetRsaGenKeyParameters())
                        return;
                }
                else if (Action == ActionType.Encrypt || Action == ActionType.Decrypt)
                {
                    if (!GetRsaEncryptDecryptParameters())
                        return;
                }

                break;

        }
        #endregion

        IsParsed = true;
    }

    bool IsHelp(string p)
    {
        p = p.ToLower();
        return (p.Equals("?") || p.Equals("help")) ? true : false;
    }

    Dictionary<string, string> ParseCmdLine(string[] args, int startIndex, ref bool error)
    {
        Dictionary<string, string> options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (args.Length < (startIndex + 1))
            Message += "Not enough arguments specified.";
        else
        {
            string pattern = "(?<argname>.*?):(?<argvalue>.*)";
            //string pattern = @"(?<argname>/\w+):(?<argvalue>.*)";
            for (int i = startIndex; i < args.Length; i++)
            {
                Match match = Regex.Match(args[i], pattern);

                // If match not found, command line args are improperly formed.
                if (match.Success)
                {
                    options[match.Groups["argname"].Value.TrimStart('/')] =       //.ToLower()
                        match.Groups["argvalue"].Value;
                }
                else
                {
                    Message = "The command line arguments are not valid or are improperly formed. Use 'argname:argvalue' for extended arguments.\r\n";
                    break;
                }
            }
        }
        error = !string.IsNullOrWhiteSpace(Message);
        return options;
    }

    bool GetBase64Parameters()
    {
        bool ok = true;

        if (Parms.Keys.Contains(__data))
        {
            Data = Parms[__data];
            Parms.Remove(__data);
        }
        else
        {
            Message += "  * Data not specified.\r\n";
            ok = false;
        }
        return ok;
    }

    bool GetRijndaelParameters()
    {
        bool ok = true;

        if (Parms.Keys.Contains(__data))
        {
            Data = Parms[__data];
            Parms.Remove(__data);
        }
        else
        {
            Message += "  * Data not specified.\r\n";
            ok = false;
        }
        
        if (Parms.Keys.Contains(__passphrase))
        {
            PassPhrase = Parms[__passphrase];
            Parms.Remove(__passphrase);
        }
        else
        {
            Message += "  * Pass phrase not specified.\r\n";
            ok = false;
        }

        if (Parms.Keys.Contains(__saltvalue))
        {
            SaltValue = Parms[__saltvalue];
            Parms.Remove(__saltvalue);
        }
        else
        {
            Message += "  * Salt value not specified.\r\n";
            ok = false;
        }

        if (Parms.Keys.Contains(__initializationvector))
        {
            InitializationVector = Parms[__initializationvector];
            Parms.Remove(__initializationvector);
        }
        else
        {
            Message += "  * Initialization vector not specified.\r\n";
            ok = false;
        }

        return ok;
    }

    bool GetRsaGenKeyParameters()
    {
        bool ok = true;

        if (Parms.Keys.Contains(__keycontainername))
        {
            KeyContainerName = Parms[__keycontainername];
            if (string.IsNullOrWhiteSpace(KeyContainerName))
            {
                Message += "  * Key container name not specified.\r\n";
                ok = false;
            }                
            Parms.Remove(__keycontainername);
        }        

        if (Parms.Keys.Contains(__keyfile))
        {            
            KeyFile = Parms[__keyfile];
            if (string.IsNullOrWhiteSpace(KeyFile))
            {
                Message += "  * Key File path not specified.\r\n";
                ok = false;
            }
            Parms.Remove(__keyfile);
        }
        
        //else
        //{
        //    Message += "  * Key File path not specified.\r\n";
        //    ok = false;
        //}

        return ok;
    }

    bool GetRsaEncryptDecryptParameters()
    {
        bool ok = true;

        if (Parms.Keys.Contains(__data))
        {
            Data = Parms[__data];
            Parms.Remove(__data);
        }
        else
        {
            Message += "  * Data not specified.\r\n";
            ok = false;
        }

        if (!Parms.Keys.Contains(__keycontainername) && !Parms.Keys.Contains(__keyfile))
        {
            Message += "  * Specify either key container name or key file";
            ok = false;
        }
        if (Parms.Keys.Contains(__keycontainername))
        {            
            KeyContainerName = Parms[__keycontainername];

            Parms.Remove(__keycontainername);
        }
        if (Parms.Keys.Contains(__keyfile))
        {
            if (!System.IO.File.Exists(Parms[__keyfile]))
            {
                Message += "  * Unable to resolve Key File as path.\r\n";
                ok = false;
            }
            else
                KeyFile = Parms[__keyfile];

            Parms.Remove(__keyfile);
        }
        if (Parms.Keys.Contains(__flags))
        {
            if (Enum.TryParse<CspProviderFlags>(Parms[__flags], true, out CspProviderFlags f))
                Flags = f;
            else
            {
                Message += "  * Unknown CspProviderFlags.\r\n";
                ok = false;
            }
            Parms.Remove(__flags);
        }
        else
            Flags = CspProviderFlags.NoFlags;
                
        return ok;
    }
}

enum AlgorithmType
{
    None,
    Base64,
    Rsa,
    Rijndael
}
enum ActionType
{
    None,
    Encode,
    Decode,
    Encrypt,
    Decrypt,
    GenKey
}
class Parameter
{
    public string Key { get; set; }
    public Type Type { get; set; }
    public string HelpText { get; set; }
}
