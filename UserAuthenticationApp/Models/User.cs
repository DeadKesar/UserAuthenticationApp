using System;

namespace UserAuthenticationApp.Models
{
    public class User
    {
        // Свойство для хранения имени пользователя
        public string Username { get; set; }

        // Свойство для хранения хэша пароля (используем массив байтов)
        public byte[] PasswordHash { get; set; }

        // Свойство для хранения соли для пароля (используем массив байтов)
        public byte[] Salt { get; set; }

        // Свойство для блокировки учетной записи пользователя
        public bool IsBlocked { get; set; }

        // Свойство для включения ограничений на пароли (наличие цифр, прописных и строчных букв, символов)
        public bool PasswordRestrictionsEnabled { get; set; }

        // Конструктор без параметров для возможности сериализации (если потребуется)
        public User()
        {
        }

        // Конструктор с параметрами для удобного создания объекта пользователя
        public User(string username, byte[] passwordHash, byte[] salt, bool isBlocked = false, bool passwordRestrictionsEnabled = false)
        {
            Username = username ?? throw new ArgumentNullException(nameof(username));
            PasswordHash = passwordHash ?? throw new ArgumentNullException(nameof(passwordHash));
            Salt = salt ?? throw new ArgumentNullException(nameof(salt));
            IsBlocked = isBlocked;
            PasswordRestrictionsEnabled = passwordRestrictionsEnabled;
        }

        // Переопределение метода ToString() для удобного отображения информации о пользователе
        public override string ToString()
        {
            return $"Пользователь: {Username}, Заблокирован: {IsBlocked}, Ограничения на пароль: {PasswordRestrictionsEnabled}";
        }
    }
}
