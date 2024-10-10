using System;
using System.Linq;
using System.Windows;
using UserAuthenticationApp.Models;
using UserAuthenticationApp.Services;
using UserAuthenticationApp.Utilities;

namespace UserAuthenticationApp.Views
{
    public partial class UserWindow : Window
    {
        private readonly User _currentUser;
        private readonly UserRepository _userRepository;
        private readonly CryptoService _cryptoService;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public UserWindow(User currentUser, UserRepository userRepository, CryptoService cryptoService, byte[] key, byte[] iv)
        {
            InitializeComponent();
            _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _iv = iv ?? throw new ArgumentNullException(nameof(iv));
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

            // Проверка старого пароля
            var hashedPassword = _cryptoService.HashPassword(oldPassword, _currentUser.Salt);
            if (!hashedPassword.SequenceEqual(_currentUser.PasswordHash))
            {
                MessageTextBlock.Text = "Неправильный старый пароль.";
                return;
            }

            // Проверка совпадения нового пароля и подтверждения
            if (newPassword != confirmPassword)
            {
                MessageTextBlock.Text = "Новый пароль и подтверждение не совпадают.";
                return;
            }

            // Проверка нового пароля на соответствие требованиям
            bool restrictionsEnabled = _currentUser.PasswordRestrictionsEnabled;
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
            _currentUser.Salt = newSalt;
            _currentUser.PasswordHash = newPasswordHash;

            // Обновление пользователя в репозитории
            _userRepository.UpdateUser(_currentUser);
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
