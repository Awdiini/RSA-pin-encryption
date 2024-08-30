using System;

namespace main
{
    class Program
    {
        static void Main(string[] args)
        {
            // Example values
            string pin = "4321"; // Your PIN
            string cardNumber = "5213636125746050"; // Your card number
            string publicKeyBase64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt8MFxB0tQiBpIXLwMYQOF35JqN4gDqKjLPvlwtBzj+iyo/ogXDkVex1ls8xEe4/gC68Lf/LpkUVORo31yOvW3MYkGEZ/xzwF8+5fxQsNJb/bA0xpNtikN0FaEYqz/FTpn2r0vgB4Km3K5fbcMfjDyIw1YUWQZc0ShSPjO959lEUvRddoIXyzrRGbp8aigwye7dHwumFzeXcmGNX6TY3TZ6qU0p7ol6pS4XSeNIsW93tT62WvNAcOOgs99WXQMEVlZ9IYnig9c6qUOLyHcG6JJF0PyeH2FWLqBoT17b575uBrUC93FQ9Nba5trJBinZSQXzV6RoyHuLU/z9ZIGdySxQIDAQAB"; // Base64 encoded public key

            string encryptedPin = PinEncryption.EncryptPin(pin, cardNumber, publicKeyBase64);
            Console.WriteLine("Encrypted PIN: " + encryptedPin);
        }
    }
}
