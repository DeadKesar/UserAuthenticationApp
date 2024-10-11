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
        private readonly string _username;
        private readonly UserRepository _userRepository;
        private readonly CryptoService _cryptoService;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public ChangePasswordWindow(UserRepository userRepository, CryptoService cryptoService, byte[] key, byte[] iv, string username)
        {
            InitializeComponent();

            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _iv = iv ?? throw new ArgumentNullException(nameof(iv));
            _username = username ?? throw new ArgumentNullException(nameof(username));
        }

        private void ChangePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            string oldPassword = OldPasswordBox.Password;
            string newPassword = NewPasswordBox.Password;
            string confirmPassword = ConfirmPasswordBox.Password;

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
                MessageTextBlock.Text = "Старый пароль введен неверно.";
                return;
            }

            // Проверка нового пароля и подтверждения
            if (newPassword != confirmPassword)
            {
                MessageTextBlock.Text = "Пароль и подтверждение не совпадают.";
                return;
            }

            // Проверка нового пароля на соответствие требованиям
            if (!PasswordValidator.ValidatePassword(newPassword, user.PasswordRestrictionsEnabled))
            {
                MessageTextBlock.Text = "Новый пароль не соответствует требованиям. Строчные и прописные буквы и цифры и арифм символы.";
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

            // Обновление пароля пользователя
            user.PasswordHash = newPasswordHash;
            user.Salt = newSalt;

            _userRepository.UpdateUser(user);
            _userRepository.SaveUsers(_key, _iv);

            // Успешная смена пароля
            MessageBox.Show("Пароль успешно изменен.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
