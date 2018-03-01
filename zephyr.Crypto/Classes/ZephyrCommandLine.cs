using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public class ZephyrCommandLine
{
    public void Main(string[] args)
    {
        foreach( string arg in args )
            Console.WriteLine( arg );

        Environment.Exit( -1 );
    }
}