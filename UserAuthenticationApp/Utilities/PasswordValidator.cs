using System;
using System.Linq;

namespace UserAuthenticationApp.Utilities
{
    public static class PasswordValidator
    {
        // Метод для проверки пароля на соответствие требованиям
        public static bool ValidatePassword(string password, bool restrictionsEnabled)
        {
            // Если ограничения не включены, просто возвращаем true
            if (!restrictionsEnabled)
            {
                return true;
            }

            // Проверка, содержит ли пароль строчные буквы
            bool hasLowerCase = password.Any(char.IsLower);

            // Проверка, содержит ли пароль прописные буквы
            bool hasUpperCase = password.Any(char.IsUpper);

            // Проверка, содержит ли пароль цифры
            bool hasDigit = password.Any(char.IsDigit);

            // Проверка, содержит ли пароль знаки препинания или арифметические символы
            bool hasSpecialChar = password.Any(ch => char.IsPunctuation(ch) || "+-*/=".Contains(ch));

            // Пароль считается валидным, если он соответствует всем критериям
            return hasLowerCase && hasUpperCase && hasDigit && hasSpecialChar;
        }

        // Опционально, метод для проверки длины пароля
        public static bool ValidatePasswordLength(string password, int minLength = 8)
        {
            // Проверяем, что пароль имеет минимально допустимую длину
            return password.Length >= minLength;
        }
    }
}
