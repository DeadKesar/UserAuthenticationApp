using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UserAuthenticationApp.Models;
using UserAuthenticationApp.Services;

namespace UserAuthenticationApp.Services
{
    public class UserRepository
    {
        // Список пользователей
        private List<User> _users = new List<User>();

        // Имя файла для хранения данных
        private const string FileName = "users.dat";

        // Методы для доступа к пользователям
        public List<User> GetAllUsers()
        {
            return _users;
        }

        public User GetUser(string username)
        {
            return _users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        }

        public void AddUser(User user)
        {
            if (_users.Any(u => u.Username.Equals(user.Username, StringComparison.OrdinalIgnoreCase)))
            {
                throw new Exception($"Пользователь с именем {user.Username} уже существует.");
            }

            _users.Add(user);
        }

        public void UpdateUser(User updatedUser)
        {
            var existingUser = GetUser(updatedUser.Username);
            if (existingUser != null)
            {
                existingUser.PasswordHash = updatedUser.PasswordHash;
                existingUser.Salt = updatedUser.Salt;
                existingUser.IsBlocked = updatedUser.IsBlocked;
                existingUser.PasswordRestrictionsEnabled = updatedUser.PasswordRestrictionsEnabled;
            }
            else
            {
                throw new Exception($"Пользователь с именем {updatedUser.Username} не найден.");
            }
        }

        public void DeleteUser(string username)
        {
            var user = GetUser(username);
            if (user != null)
            {
                _users.Remove(user);
            }
            else
            {
                throw new Exception($"Пользователь с именем {username} не найден.");
            }
        }

        // Метод для загрузки пользователей из зашифрованного файла
        public void LoadUsers(byte[] key, byte[] iv)
        {
            if (!File.Exists(FileName))
            {
                // Если файл не существует, создаем пустой список пользователей
                _users = new List<User>();
                return;
            }

            try
            {
                using (FileStream fs = new FileStream(FileName, FileMode.Open, FileAccess.Read))
                {
                    byte[] ivFromFile = new byte[16];
                    fs.Read(ivFromFile, 0, ivFromFile.Length);

                    byte[] saltFromFile = new byte[16];
                    fs.Read(saltFromFile, 0, saltFromFile.Length);

                    byte[] encryptedData = new byte[fs.Length - ivFromFile.Length - saltFromFile.Length];
                    fs.Read(encryptedData, 0, encryptedData.Length);

                    // Расшифровываем данные
                    CryptoService crypto = new CryptoService();
                    byte[] decryptedData = crypto.DecryptData(encryptedData, key, ivFromFile);

                    // Десериализуем список пользователей из JSON
                    string json = Encoding.UTF8.GetString(decryptedData);
                    _users = JsonSerializer.Deserialize<List<User>>(json) ?? new List<User>();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Ошибка при загрузке данных пользователей: " + ex.Message);
            }
        }

        // Метод для сохранения пользователей в зашифрованный файл
        public void SaveUsers(byte[] key, byte[] iv)
        {
            try
            {
                // Сериализуем список пользователей в JSON
                string json = JsonSerializer.Serialize(_users);
                byte[] data = Encoding.UTF8.GetBytes(json);

                // Шифруем данные
                CryptoService crypto = new CryptoService();
                byte[] encryptedData = crypto.EncryptData(data, key, iv);

                using (FileStream fs = new FileStream(FileName, FileMode.Create, FileAccess.Write))
                {
                    // Сохраняем IV и соль в начале файла
                    fs.Write(iv, 0, iv.Length);
                    // Для соли используем salt из первого пользователя (предполагается, что соль одинакова для всех)
                    // Альтернативно, можно хранить отдельную соль для репозитория
                    byte[] repositorySalt = crypto.GenerateSalt();
                    fs.Write(repositorySalt, 0, repositorySalt.Length);
                    // Сохраняем зашифрованные данные
                    fs.Write(encryptedData, 0, encryptedData.Length);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Ошибка при сохранении данных пользователей: " + ex.Message);
            }
        }

        // Метод для безопасного удаления файла (перезапись и удаление)
        public void SecureDelete(string filePath)
        {
            if (File.Exists(filePath))
            {
                try
                {
                    FileInfo fileInfo = new FileInfo(filePath);
                    long fileLength = fileInfo.Length;

                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                    {
                        // Перезаписываем файл случайными данными
                        byte[] data = new byte[4096];
                        using (var rng = RandomNumberGenerator.Create())
                        {
                            long totalWritten = 0;
                            while (totalWritten < fileLength)
                            {
                                rng.GetBytes(data);
                                int toWrite = (int)Math.Min(data.Length, fileLength - totalWritten);
                                fs.Write(data, 0, toWrite);
                                totalWritten += toWrite;
                            }
                        }
                    }

                    // Удаляем файл
                    File.Delete(filePath);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Ошибка при безопасном удалении файла {filePath}: {ex.Message}");
                }
            }
        }
    }
}
