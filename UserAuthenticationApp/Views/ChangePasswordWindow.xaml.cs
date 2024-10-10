using System;
using System.Linq;
using System.Windows;
using UserAuthenticationApp.Models;
using UserAuthenticationApp.Services;
using UserAuthenticationApp.Utilities;

namespace UserAuthenticationApp.Views
{
    public partial class ChangePasswordWindow : Window
    {
        private readonly UserRepository _userRepository;
        private readonly CryptoService _cryptoService;
        private readonly byte[] _key;
        private readonly byte[] _iv;
        private readonly string _username;

        public ChangePasswordWindow(UserRepository userRepository, CryptoService cryptoService, byte[] key, byte[] iv, string username)
        {
            InitializeComponent();
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _iv = iv ?? throw new ArgumentNullException(nameof(iv));
            _username = username ?? throw new ArgumentNullException(nameof(username));
        }

        // Обработчик нажатия на кнопку "Сменить пароль"
        private void ChangePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            string oldPassword = OldPasswordBox.Password;
            string newPassword = NewPasswordBox.Password;
            string confirmPassword = ConfirmPasswordBox.Password;

            // Проверка на заполненность полей
            if (string.IsNullOrEmpty(oldPassword) || string.IsNullOrEmpty(newPassword) || string.IsNullOrEmpty(confirmPassword))
            {
                MessageTextBlock.Text = "Все поля должны быть заполнены.";
                return;
            }

            // Получаем пользователя
            var user = _userRepository.GetUser(_username);
            if (user == null)
            {
                MessageTextBlock.Text = "Пользователь не найден.";
                return;
            }

            // Проверка старого пароля
            var hashedOldPassword = _cryptoService.HashPassword(oldPassword, user.Salt);
            if (!hashedOldPassword.SequenceEqual(user.PasswordHash))
            {
                MessageTextBlock.Text = "Неправильный старый пароль.";
                return;
            }

            // Проверка совпадения нового пароля и подтверждения
            if (newPassword != confirmPassword)
            {
                MessageTextBlock.Text = "Новый пароль и его подтверждение не совпадают.";
                return;
            }

            // Проверка нового пароля на соответствие требованиям
            bool restrictionsEnabled = user.PasswordRestrictionsEnabled;
            if (!PasswordValidator.ValidatePassword(newPassword, restrictionsEnabled))
            {
                MessageTextBlock.Text = "Новый пароль не соответствует требованиям.";
                return;
            }

            if (!PasswordValidator.ValidatePasswordLength(newPassword))
            {
                MessageTextBlock.Text = "Новый пароль должен быть длиной не менее 8 символов.";
                return;
            }

            // Генерация новой соли и хеширование нового пароля
            byte[] newSalt = _cryptoService.GenerateSalt();
            byte[] newPasswordHash = _cryptoService.HashPassword(newPassword, newSalt);

            // Обновляем данные пользователя
            user.Salt = newSalt;
            user.PasswordHash = newPasswordHash;
            _userRepository.UpdateUser(user);
            _userRepository.SaveUsers(_key, _iv);

            // Успешная смена пароля
            MessageTextBlock.Text = "Пароль успешно изменен.";
            MessageTextBlock.Foreground = System.Windows.Media.Brushes.Green;

            // Очистка полей
            OldPasswordBox.Clear();
            NewPasswordBox.Clear();
            ConfirmPasswordBox.Clear();
        }

        // Обработчик нажатия на кнопку "Отмена"
        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
