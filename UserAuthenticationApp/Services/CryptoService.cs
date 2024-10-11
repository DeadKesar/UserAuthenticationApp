using System;
using System.Security.Cryptography;
using System.Text;

namespace UserAuthenticationApp.Services
{
    public class CryptoService
    {
        // Количество итераций для PBKDF2
        private const int IterationCount = 10000;

        // Длина ключа для AES (256 бит = 32 байта)
        private const int KeySize = 32;

        // Длина соли (128 бит = 16 байт)
        private const int SaltSize = 16;

        // Длина вектора инициализации для AES (128 бит = 16 байт)
        private const int IvSize = 16;

        // Генерация криптографического ключа на основе парольной фразы и соли
        public byte[] GenerateKey(string passphrase, byte[] salt)
        {
            using (var keyGenerator = new Rfc2898DeriveBytes(passphrase, salt, IterationCount, HashAlgorithmName.SHA256))
            {
                return keyGenerator.GetBytes(KeySize); // Генерация 256-битного ключа
            }
        }

        // Генерация случайной соли
        public byte[] GenerateSalt()
        {
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt); // Заполнение случайными байтами
            }
            return salt;
        }

        // Генерация случайного вектора инициализации (IV)
        public byte[] GenerateIV()
        {
            byte[] iv = new byte[IvSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv); // Заполнение случайными байтами
            }
            return iv;
        }

        // Хеширование пароля с использованием SHA-256
        public byte[] HashPassword(string password, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] combinedBytes = new byte[passwordBytes.Length + salt.Length];

                // Комбинирование пароля с солью
                Buffer.BlockCopy(passwordBytes, 0, combinedBytes, 0, passwordBytes.Length);
                Buffer.BlockCopy(salt, 0, combinedBytes, passwordBytes.Length, salt.Length);

                // Вычисление хэша
                return sha256.ComputeHash(combinedBytes);
            }
        }

        // Шифрование данных с использованием AES в режиме CFB
        public byte[] EncryptData(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CFB;
                aes.Padding = PaddingMode.PKCS7; // Заполнение данных

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // Расшифровка данных с использованием AES в режиме CFB
        public byte[] DecryptData(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CFB;
                aes.Padding = PaddingMode.PKCS7; // Заполнение данных

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }
    }
}
