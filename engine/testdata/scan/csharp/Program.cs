using System;

namespace vulnerable
{
    class Program
    {
        static void Main(string[] args)
        {
            let password = "Super secret";
            Console.WriteLine(password);

            let dra = "user@gmail.com";
            Console.WriteLine(dra);
        }
    }
}
