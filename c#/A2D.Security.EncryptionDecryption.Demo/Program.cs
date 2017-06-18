using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace A2D.Security.EncryptionDecryption.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            RSADecryptor decryptor = new RSADecryptor();

            //或者decryptor.LoadXmlDefinationFromString();
            decryptor.LoadXmlDefinationFromFile(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rsa_private_key.xml"));


            Console.WriteLine(decryptor.Decrypt(@"VPAVCnE6yuaSWNE09BUaEnb9xXXt4evfmm6mUOF6di3rN0BsA8fR2ETEBgqNxzWG7FBZqR/uIGZr
ul81SFz72pA+jdvlZfzBwAdO0Iv1MpWrrmWaisW7M9VLWI74LxUtPmmM84CjhZ0hzdXyK5yr8ani
5P0gar8N8CLqkthOKz180MPnUOYj1Pln3HfgUrT22Dy8KscIhwMLltvLYakRLCfI4f62Hd5Uwt9H
rASlQkQB5gNZA0tDLy+s1V8ToezbtbOT5gD7gWn122QBitTiRKHewjyU4FrJcTsllwzHNfpJ6fsd
VWBiLh3KwqHmRy6rlCYIvvY2HhgZ9c4o5DMA7EV2+siCLyvn1xNGnz2eCE/cCSOCcTSvJsZAIsp+
Of9ObyHZ3Hx/HXIeH6ECLlXBfOe3KmXGu730R09iCpXl+YS5oiQEPxm04Vdq2H0O/qX7LI6Gvl23
L26sgMDQ5dbnudnrHMCtpdM4QK7rOHp76IRDVNPuf0b+Y1mX9cInQWlP"));

            Console.ReadKey();
        }
    }
}
