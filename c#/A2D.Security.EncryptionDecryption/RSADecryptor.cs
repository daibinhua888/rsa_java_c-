using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace A2D.Security.EncryptionDecryption
{
    public class RSADecryptor
    {
        public void LoadXmlDefinationFromFile(string xmlFile)
        {
            if (!File.Exists(xmlFile))
                throw new FileNotFoundException();

            this.XmlDefination = File.ReadAllText(xmlFile);
        }

        public void LoadXmlDefinationFromString(string xmlDefination)
        {
            this.XmlDefination = xmlDefination;
        }

        public string XmlDefination { get; set; }

        public String Decrypt(string base64String)
        {
            String result = null;
            byte[] input = Convert.FromBase64String(base64String);
            RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider();
            rsaService.FromXmlString(this.XmlDefination);

            if (input.Length <= 128)
            {
                byte[] output = rsaService.Decrypt(input, false);
                result = Encoding.UTF8.GetString(output);
                return result;
            }

            List<byte> bytes = new List<byte>();

            for (int i = 0; i < input.Length; i += 128)
            {
                byte[] piece = input.Skip(i).Take(128).ToArray();
                byte[] doFinal = rsaService.Decrypt(piece, false);
                bytes.AddRange(doFinal);
            }

            return Encoding.UTF8.GetString(bytes.ToArray());
        }
    }
}
