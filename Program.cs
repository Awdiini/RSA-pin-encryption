using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

class Program
{
    static void Main(string[] args)
    {
        // Example inputs
  
        string PIN = "4321";  // Replace with actual PIN
        string CardNumber = "5213636125746050";  // Replace with actual card number
        string PublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt8MFxB0tQiBpIXLwMYQOF35JqN4gDqKjLPvlwtBzj+iyo/ogXDkVex1ls8xEe4/gC68Lf/LpkUVORo31yOvW3MYkGEZ/xzwF8+5fxQsNJb/bA0xpNtikN0FaEYqz/FTpn2r0vgB4Km3K5fbcMfjDyIw1YUWQZc0ShSPjO959lEUvRddoIXyzrRGbp8aigwye7dHwumFzeXcmGNX6TY3TZ6qU0p7ol6pS4XSeNIsW93tT62WvNAcOOgs99WXQMEVlZ9IYnig9c6qUOLyHcG6JJF0PyeH2FWLqBoT17b575uBrUC93FQ9Nba5trJBinZSQXzV6RoyHuLU/z9ZIGdySxQIDAQAB";  // Replace with actual Base64-encoded public key

        // Create the PIN block
        string hexPINBlock = ("0" + PIN.Length + PIN).PadRight(16, 'F');

        // Create the Card lock block (12 rightmost digits excluding the last digit)
        CardNumber = CardNumber.Substring(0, CardNumber.Length - 1);
        string hexCardlock = ("0000" + CardNumber.Substring(CardNumber.Length - 12));

        // XOR the PIN block and Card lock block
        long dec1 = Convert.ToInt64(hexPINBlock, 16);
        long dec2 = Convert.ToInt64(hexCardlock, 16);
        long result = dec1 ^ dec2;
        string hexResult = result.ToString("X");

        // Ensure the result is 16 characters long
        if (hexResult.Length < 16)
        {
            hexResult = hexResult.PadLeft(16, '0');
        }

        // Convert the hex result to bytes
        byte[] pinBlockBytes = Enumerable.Range(0, hexResult.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(hexResult.Substring(x, 2), 16))
            .ToArray();

        // RSA Encryption
        try
        {
            byte[] publicKeyBytes = Convert.FromBase64String(PublicKey);
            RsaKeyParameters rsaKeyParameters;
            Asn1Object asn1Object;
            using (var stream = new Asn1InputStream(publicKeyBytes))
            {
                asn1Object = stream.ReadObject();
                rsaKeyParameters = PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(asn1Object)) as RsaKeyParameters;
            }

            RSAParameters rsaParameters = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(rsaParameters);
                byte[] encryptedBytes = rsa.Encrypt(pinBlockBytes, RSAEncryptionPadding.OaepSHA1); // Use appropriate padding

                // Convert encrypted bytes to Base64 string
                string encryptedText = Convert.ToBase64String(encryptedBytes);
                Console.WriteLine("Encrypted PIN Block: " + encryptedText); // Output the encrypted PIN block
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }






        
    }






    
}




