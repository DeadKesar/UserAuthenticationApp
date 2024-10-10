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

        // Метод для генерации криптографического ключа на основе парольной фразы и соли
        public byte[] GenerateKey(string passphrase, byte[] salt)
        {
            using (var keyGenerator = new Rfc2898DeriveBytes(passphrase, salt, IterationCount, HashAlgorithmName.SHA256))
            {
                return keyGenerator.GetBytes(KeySize); // Генерация 256-битного ключа
            }
        }

        // Метод для генерации случайной соли
        public byte[] GenerateSalt()
        {
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt); // Заполняем соль случайными байтами
            }
            return salt;
        }

        // Метод для генерации случайного вектора инициализации (IV)
        public byte[] GenerateIV()
        {
            byte[] iv = new byte[IvSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv); // Заполняем IV случайными байтами
            }
            return iv;
        }

        // Метод для хеширования пароля с использованием SHA-256
        public byte[] HashPassword(string password, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] combinedBytes = new byte[passwordBytes.Length + salt.Length];

                // Комбинируем пароль с солью
                Buffer.BlockCopy(passwordBytes, 0, combinedBytes, 0, passwordBytes.Length);
                Buffer.BlockCopy(salt, 0, combinedBytes, passwordBytes.Length, salt.Length);

                // Возвращаем хеш пароля с солью
                return sha256.ComputeHash(combinedBytes);
            }
        }

        // Метод для шифрования данных с использованием AES в режиме CFB
        public byte[] EncryptData(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CFB;
                aes.Padding = PaddingMode.PKCS7; // Заполнение данных для шифрования

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // Метод для расшифровки данных с использованием AES в режиме CFB
        public byte[] DecryptData(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CFB;
                aes.Padding = PaddingMode.PKCS7; // Заполнение данных для расшифровки

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }
    }
}
