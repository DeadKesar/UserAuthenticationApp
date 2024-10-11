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
        private readonly User _user;
        private readonly UserRepository _userRepository;
        private readonly CryptoService _cryptoService;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public UserWindow(User user, UserRepository userRepository, CryptoService cryptoService, byte[] key, byte[] iv)
        {
            InitializeComponent();

            _user = user ?? throw new ArgumentNullException(nameof(user));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _iv = iv ?? throw new ArgumentNullException(nameof(iv));
        }

        private void ChangePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            string oldPassword = OldPasswordBox.Password;
            string newPassword = NewPasswordBox.Password;
            string confirmPassword = ConfirmPasswordBox.Password;

            // Проверка старого пароля
            var hashedOldPassword = _cryptoService.HashPassword(oldPassword, _user.Salt);
            if (!hashedOldPassword.SequenceEqual(_user.PasswordHash))
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
            if (!PasswordValidator.ValidatePassword(newPassword, _user.PasswordRestrictionsEnabled))
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

            // Обновляем данные пользователя
            _user.Salt = newSalt;
            _user.PasswordHash = newPasswordHash;

            // Сохраняем изменения
            _userRepository.UpdateUser(_user);
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
