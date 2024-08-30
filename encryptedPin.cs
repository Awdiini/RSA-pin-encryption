using System;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace main
{
    public static class PinEncryption
    {
        public static string EncryptPin(string PIN, string CardNumber, string PublicKey)
        {
            string hexPINBlock = (("0" + PIN.Length + PIN).PadRight(16, 'F'));
            CardNumber = CardNumber.Substring(0, CardNumber.Length - 1); 
            string hexCardlock = ("0000" + CardNumber.Substring(CardNumber.Length - 12));
            long dec1 = Convert.ToInt64(hexPINBlock, 16);
            long dec2 = Convert.ToInt64(hexCardlock, 16);
            long result = dec1 ^ dec2;
            string hexResult = result.ToString("X");

            if (hexResult.Length < 16)
            {
                hexResult = "0" + hexResult;
            }
            int NumberChars = hexResult.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexResult.Substring(i, 2), 16);
            }

            string hexStringResult = BitConverter.ToString(bytes).Replace("-", "");
            byte[] publicKeyBytes = Convert.FromBase64String(PublicKey);  //KINDLY GET "PublicKey" from GetPublicKey API
            RsaKeyParameters rsaKeyParameters;
            Asn1Object asn1Object;
            using (var stream = new Asn1InputStream(publicKeyBytes))
            {
                asn1Object = stream.ReadObject();
                rsaKeyParameters = PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(asn1Object)) as RsaKeyParameters;
            }
            RSAParameters rSAParameters = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rSAParameters);
                byte[] plainBytes = Encoding.UTF8.GetBytes(hexStringResult);
                bool OAEP = false; // or true, depending on your specific use case
                byte[] encryptedBytes = rsa.Encrypt(plainBytes, OAEP);
                string encryptedText = Convert.ToBase64String(encryptedBytes);
                return encryptedText;
            }
        }
    }
}
