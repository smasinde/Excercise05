using System;
using System.IO;
using System.Collections.Generic;
using System.Xml.Serialization;
using System.Text;
using System.Security.Cryptography;

namespace Exercise05
{
    class Program
    {
        static void Main(string[] args)
        {
            // Creates unencryted xml
            Customers customers = new Customers { customer = new Customer { Name = "Bob Smith", CreditCard = "1234-5678-9012-3456", Password = "Pa$$w0rd" } };

            var path = Environment.CurrentDirectory + "-CustomerList.xml";
            FileStream file = File.Create(path);

            XmlSerializer serializerXml =
                new XmlSerializer(typeof(Customers));

            serializerXml.Serialize(file, customers);
            file.Close();

            // Read unencryted xml
            StreamReader reader = new StreamReader(path);

            Customers loadedXml = serializerXml.Deserialize(reader) as Customers;
            reader.Close();

            // cc string encryption
            string encrypt = Encrypt(loadedXml.customer.CreditCard);

            loadedXml.customer.CreditCard = encrypt;

            // Password salt and hash
            string passwrd = loadedXml.customer.Password;
            var salt = GenSalt();
            var hashed = GetHash(Encoding.UTF8.GetBytes(passwrd), Encoding.UTF8.GetBytes(salt));

            loadedXml.customer.Password = hashed;

            // Write protected xml
            var path1 = Environment.CurrentDirectory + "-CustomerList-protected.xml";
            FileStream safeFile = File.Create(path1);
            serializerXml.Serialize(safeFile, loadedXml);
            safeFile.Close();

            // Read protected file and decrypt credit card number
            StreamReader reader1 = new StreamReader(path1);
            Customers loadProtectedXml = serializerXml.Deserialize(reader1) as Customers;
            reader1.Close();

            Console.WriteLine($"Protected file unencryted:: {loadProtectedXml.customer.CreditCard}");
            Console.WriteLine(Decrypt(loadProtectedXml.customer.CreditCard));

        }

        public static string GetHash(byte[] bytesToHash, byte[] salt)
        {
            var byteRes = new Rfc2898DeriveBytes(bytesToHash, salt, 2000);
            return Convert.ToBase64String(byteRes.GetBytes(24));
        }
        public static string GenSalt()
        {
            var bytes = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
        public static string Encrypt(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            var encrypted = getAes().CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
            return Convert.ToBase64String(encrypted);
        }
        public static string Decrypt(string encrypted)
        {
            var bytes = Convert.FromBase64String(encrypted);
            var decrypted = getAes().CreateDecryptor().TransformFinalBlock(bytes, 0, bytes.Length);
            return Encoding.UTF8.GetString(decrypted);
        }
        static Aes getAes()
        {
            var keyBytes = new byte[16];
            var secretKey = Encoding.UTF8.GetBytes("technobrain");
            Array.Copy(secretKey, keyBytes, Math.Min(keyBytes.Length, secretKey.Length));

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 128;
            aes.Key = keyBytes;
            aes.IV = keyBytes;

            return aes;
        }
    }

    public class Customers
    {
        public Customer customer { get; set; }
    }
    public class Customer
    {
        public string Name { get; set; }
        public string CreditCard { get; set; }
        public string Password { get; set; }
    }

}
