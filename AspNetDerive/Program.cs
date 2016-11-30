using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security.Cryptography;

namespace LowLevelDesign.AspNetDerive
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = null, context = null, label = null;
            string[] labels = new string[0];
            bool showhelp = false;

            var p = new OptionSet
            {
                { "k|key=", "the validation key (in hex)", v => key = v },
                { "c|context=", "the context", v => context = v },
                { "l|labels=", "the labels, separated by commas", v => label = v },
                { "h|help", "show this message and exit", v => showhelp = v != null },
                { "?", "show this message and exit", v => showhelp = v != null }
            };

            try {
                p.Parse(args).FirstOrDefault();
            } catch (OptionException ex) {
                Console.Error.Write("ERROR: invalid argument, ");
                Console.Error.WriteLine(ex.Message);
                Console.Error.WriteLine();
                showhelp = true;
            } 
            if (!showhelp && key == null) {
                Console.Error.WriteLine("ERROR: the key is missing");
                Console.Error.WriteLine();
                showhelp = true;
            }
            if (label != null) {
                labels = label.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            } 
            if (!showhelp && context == null) { 
                Console.Error.WriteLine("ERROR: the context is missing");
                Console.Error.WriteLine();
                showhelp = true;
            }
            if (showhelp) {
                ShowHelp(p);
                return;
            }

            Debug.Assert(context != null);
            Debug.Assert(key != null);


            if (key.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) {
                key = key.Substring(2);
            }

            var purpose = new Purpose(context, labels);
            var keyBytes = CryptoUtil.HexToBinary(key);
            if (keyBytes == null) {
                Console.Error.WriteLine("ERROR: the key is invalid");
                Console.Error.WriteLine();
                return;
            }

            Console.WriteLine(Hexify.Hex.PrettyPrint(SP800_108.DeriveKey(
                new CryptographicKey(keyBytes), purpose).GetKeyMaterial()));
        }

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("{0} v{1} - {2}", Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyTitleAttribute>().Title,
                Assembly.GetExecutingAssembly().GetName().Version.ToString(), 
                Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyDescriptionAttribute>().Description);
            Console.WriteLine(Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyCopyrightAttribute>().Copyright);
            Console.WriteLine();
            Console.WriteLine("Usage: aspnetderive [OPTIONS]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
            Console.WriteLine();

        }
    }
}
