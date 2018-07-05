using System;
using System.IO;

namespace ExampleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var scanner = new VirusChecker.Scanner("ExampleApp");
            foreach (var file in Directory.GetFiles(args[0]))
            {
                var result = scanner.Scan(file);
                Console.WriteLine("File: {0} {1}", file, result);
            }

            Console.WriteLine("Finished");
        }
    }
}