using System;
using System.Windows;
using UserAuthenticationApp.Models;
using UserAuthenticationApp.Services;
using UserAuthenticationApp.Utilities;

namespace UserAuthenticationApp.Views
{
    public partial class NewUserWindow : Window
    {
        private readonly UserRepository _userRepository;
        private readonly CryptoService _cryptoService;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public NewUserWindow(UserRepository userRepository, CryptoService cryptoService, byte[] key, byte[] iv)
        {
            InitializeComponent();
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _iv = iv ?? throw new ArgumentNullException(nameof(iv));
        }

        // Обработчик нажатия на кнопку "Добавить"
        private void AddUserButton_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameTextBox.Text.Trim();
            string password = PasswordBox.Password;
            string confirmPassword = ConfirmPasswordBox.Password;
            bool restrictionsEnabled = RestrictionsCheckBox.IsChecked ?? false;

            // Проверка на пустое имя пользователя
            if (string.IsNullOrEmpty(username))
            {
                MessageTextBlock.Text = "Имя пользователя не может быть пустым.";
                return;
            }

            // Проверка, существует ли уже пользователь с таким именем
            if (_userRepository.GetUser(username) != null)
            {
                MessageTextBlock.Text = $"Пользователь с именем {username} уже существует.";
                return;
            }

            // Если пароль не пустой, устанавливаем его, иначе пароль будет пустым
            byte[] passwordHash = new byte[0];
            byte[] salt = new byte[0];
            if (!string.IsNullOrEmpty(password))
            {
                if (password != confirmPassword)
                {
                    MessageTextBlock.Text = "Пароль и подтверждение не совпадают.";
                    return;
                }

                // Проверка соответствия пароля требованиям
                if (!PasswordValidator.ValidatePassword(password, restrictionsEnabled))
                {
                    MessageTextBlock.Text = "Пароль не соответствует требованиям.";
                    return;
                }

                if (!PasswordValidator.ValidatePasswordLength(password))
                {
                    MessageTextBlock.Text = "Пароль должен быть длиной не менее 8 символов.";
                    return;
                }

                // Генерация соли и хеширование пароля
                salt = _cryptoService.GenerateSalt();
                passwordHash = _cryptoService.HashPassword(password, salt);
            }

            // Создание нового пользователя
            var newUser = new User
            {
                Username = username,
                PasswordHash = passwordHash,
                Salt = salt,
                IsBlocked = false,
                PasswordRestrictionsEnabled = restrictionsEnabled
            };

            // Добавление пользователя в репозиторий
            try
            {
                _userRepository.AddUser(newUser);
                _userRepository.SaveUsers(_key, _iv);

                MessageBox.Show($"Пользователь {username} успешно добавлен.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageTextBlock.Text = $"Ошибка при добавлении пользователя: {ex.Message}";
            }
        }

        // Обработчик нажатия на кнопку "Отмена"
        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
