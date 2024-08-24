using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class PinEncryption
{
    public static string EncryptPin(string pin, string cardNumber, string publicKeyBase64)
    {
        try
        {
            // Create Hex PIN Block
            string pinHex = pin.Length.ToString("X").PadLeft(2, '0') + pin.PadRight(15, 'F');
            
            // Create Hex Card Lock
            string cardHex = "0000" + cardNumber.Substring(cardNumber.Length - 12);
            
            // Perform XOR operation
            long pinDecimal = Convert.ToInt64(pinHex, 16);
            long cardDecimal = Convert.ToInt64(cardHex, 16);
            long xorResult = pinDecimal ^ cardDecimal;
            
            string xorHex = xorResult.ToString("X").PadLeft(16, '0');
            
            // Convert Hex Result to Byte Array
            byte[] bytes = new byte[xorHex.Length / 2];
            for (int i = 0; i < xorHex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(xorHex.Substring(i, 2), 16);
            }
            
            // Load and parse the public key
            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            Asn1Object asn1Object;
            using (var stream = new Asn1InputStream(publicKeyBytes))
            {
                asn1Object = stream.ReadObject();
            }
            
            var rsaKeyParameters = PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(asn1Object)) as RsaKeyParameters;
            
            var rsaParams = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                
                // Use PKCS#1 v1.5 padding if that’s the vendor’s requirement
                byte[] encryptedBytes = rsa.Encrypt(bytes, RSAEncryptionPadding.Pkcs1);
                
                return Convert.ToBase64String(encryptedBytes);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            return null;
        }
    }
}
