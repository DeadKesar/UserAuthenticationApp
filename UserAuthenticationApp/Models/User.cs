using System;

namespace UserAuthenticationApp.Models
{
    public class User
    {
        // Имя пользователя
        public string Username { get; set; }

        // Хэш пароля
        public byte[] PasswordHash { get; set; }

        // Соль для пароля
        public byte[] Salt { get; set; }

        // Флаг блокировки учетной записи
        public bool IsBlocked { get; set; }

        // Флаг включения ограничений на пароли
        public bool PasswordRestrictionsEnabled { get; set; }

        // Конструктор без параметров
        public User()
        {
        }

        // Конструктор с параметрами
        public User(string username, byte[] passwordHash, byte[] salt, bool isBlocked = false, bool passwordRestrictionsEnabled = false)
        {
            Username = username ?? throw new ArgumentNullException(nameof(username));
            PasswordHash = passwordHash ?? throw new ArgumentNullException(nameof(passwordHash));
            Salt = salt ?? throw new ArgumentNullException(nameof(salt));
            IsBlocked = isBlocked;
            PasswordRestrictionsEnabled = passwordRestrictionsEnabled;
        }

        // Переопределение ToString()
        public override string ToString()
        {
            return $"Пользователь: {Username}, Заблокирован: {IsBlocked}, Ограничения на пароль: {PasswordRestrictionsEnabled}";
        }
    }
}
