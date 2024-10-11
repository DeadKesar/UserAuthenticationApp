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

        // Соль репозитория
        private byte[] _repositorySalt;

        // IV для шифрования/расшифровки
        private byte[] _iv;

        // Публичный метод для установки соли репозитория
        public void SetRepositorySalt(byte[] repositorySalt)
        {
            if (repositorySalt == null || repositorySalt.Length != 16)
                throw new ArgumentException("Соль должна быть 16 байт.", nameof(repositorySalt));

            _repositorySalt = repositorySalt;
        }
        public void SetRepositoryIv(byte[] iv)
        {
            if (iv == null || iv.Length != 16)
                throw new ArgumentException("IV должна быть 16 байт.", nameof(iv));

            _iv = iv;
        }
        // Метод для получения соли репозитория
        public byte[] GetRepositorySalt()
        {
            return _repositorySalt;
        }

        // Метод для получения всех пользователей
        public List<User> GetAllUsers()
        {
            return _users;
        }

        // Метод для получения пользователя по имени
        public User GetUser(string username)
        {
            return _users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        }

        // Метод для добавления нового пользователя
        public void AddUser(User user)
        {
            if (_users.Any(u => u.Username.Equals(user.Username, StringComparison.OrdinalIgnoreCase)))
            {
                throw new Exception($"Пользователь с именем {user.Username} уже существует.");
            }

            _users.Add(user);
        }

        // Метод для обновления данных пользователя
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

        // Метод для удаления пользователя
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
                    // Читаем IV из файла
                    byte[] ivFromFile = new byte[16];
                    fs.Read(ivFromFile, 0, ivFromFile.Length);
                    _iv = ivFromFile; // Устанавливаем IV

                    // Читаем соль репозитория из файла
                    byte[] repositorySaltFromFile = new byte[16];
                    fs.Read(repositorySaltFromFile, 0, repositorySaltFromFile.Length);
                    SetRepositorySalt(repositorySaltFromFile); // Устанавливаем соль репозитория

                    // Читаем зашифрованные данные
                    byte[] encryptedData = new byte[fs.Length - ivFromFile.Length - repositorySaltFromFile.Length];
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
                using (FileStream fs = new FileStream(FileName, FileMode.Create, FileAccess.Write))
                {
                    CryptoService crypto = new CryptoService();

                    // Если соль репозитория еще не установлена, ловим ошибку, ибо соль репозиторию задаётся на шаге создания репозитория
                    if (_repositorySalt == null)
                    {
                        throw new Exception("У репозитория нет соли");
                    }

                    // Записываем IV и соль репозитория в начало файла
                    fs.Write(iv, 0, iv.Length);
                    fs.Write(_repositorySalt, 0, _repositorySalt.Length);

                    // Сериализуем список пользователей в JSON
                    string json = JsonSerializer.Serialize(_users);
                    byte[] data = Encoding.UTF8.GetBytes(json);

                    // Шифруем данные
                    byte[] encryptedData = crypto.EncryptData(data, key, iv);

                    // Записываем зашифрованные данные
                    fs.Write(encryptedData, 0, encryptedData.Length);
                }

                // Устанавливаем текущий IV
                _iv = iv;

                // Записываем соль и IV в отдельный файл для отладки или использования
                WriteSaltAndIV("salt_iv.txt");
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

        // Новый метод для записи соли и IV в отдельный файл
        public void WriteSaltAndIV(string filePath)
        {
            if (_repositorySalt == null || _iv == null)
                throw new InvalidOperationException("Соль репозитория или IV не установлены.");

            try
            {
                using (StreamWriter writer = new StreamWriter(filePath))
                {
                    writer.WriteLine("IV: " + BitConverter.ToString(_iv).Replace("-", ""));
                    writer.WriteLine("RepositorySalt: " + BitConverter.ToString(_repositorySalt).Replace("-", ""));
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Ошибка при записи соли и IV в файл {filePath}: {ex.Message}");
            }
        }
    }
}
