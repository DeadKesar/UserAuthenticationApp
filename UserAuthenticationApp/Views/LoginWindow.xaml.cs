﻿using System;
using System.IO;
using System.Linq;
using System.Windows;
using UserAuthenticationApp.Models;
using UserAuthenticationApp.Services;
using UserAuthenticationApp.Utilities;
using UserAuthenticationApp.Views;

namespace UserAuthenticationApp.Views
{
    public partial class LoginWindow : Window
    {
        private int _loginAttempts = 0;
        private const int MaxLoginAttempts = 3;

        private readonly UserRepository _userRepository;
        private readonly CryptoService _cryptoService;

        private byte[] _key;
        private byte[] _iv;

        public LoginWindow()
        {
            InitializeComponent();

            _userRepository = new UserRepository();
            _cryptoService = new CryptoService();

            // Запрашиваем парольную фразу при запуске программы
            if (!RequestPassphrase())
            {
                MessageBox.Show("Программа будет закрыта.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                Application.Current.Shutdown();
            }
        }

        private bool RequestPassphrase()
        {
            var passphraseWindow = new PassphraseWindow();
            if (passphraseWindow.ShowDialog() == true)
            {
                string passphrase = passphraseWindow.Passphrase;

                // Проверяем наличие файла с пользователями
                bool isFirstRun = !File.Exists("users.dat");

                if (isFirstRun)
                {
                    // Генерируем IV и соль репозитория для первого запуска
                    _iv = _cryptoService.GenerateIV();
                    byte[] repositorySalt = _cryptoService.GenerateSalt();
                    _key = _cryptoService.GenerateKey(passphrase, repositorySalt);
                    // Устанавливаем соль и IV у объекта
                    _userRepository.SetRepositorySalt(repositorySalt);
                    _userRepository.SetRepositoryIv(_iv);
                    // Создаем учетную запись администратора с хэшированным пустым паролем
                    byte[] adminSalt = _cryptoService.GenerateSalt();
                    byte[] adminPasswordHash = _cryptoService.HashPassword(string.Empty, adminSalt); // Хэш пустого пароля

                    var adminUser = new User
                    {
                        Username = "ADMIN",
                        PasswordHash = adminPasswordHash, // Хэш пустого пароля
                        Salt = adminSalt,
                        IsBlocked = false,
                        PasswordRestrictionsEnabled = false
                    };

                    _userRepository.AddUser(adminUser);

                    // Сохраняем пользователей с IV и солью репозитория
                    _userRepository.SaveUsers(_key, _iv);

                    // Записываем соль и IV в отдельный файл для отладки
                    _userRepository.WriteSaltAndIV("salt_iv.txt");

                    return true;
                }
                else
                {
                    try
                    {
                        // Считываем IV и соль репозитория из файла
                        using (FileStream fs = new FileStream("users.dat", FileMode.Open, FileAccess.Read))
                        {
                            _iv = new byte[16];
                            fs.Read(_iv, 0, _iv.Length);

                            byte[] repositorySaltFromFile = new byte[16];
                            fs.Read(repositorySaltFromFile, 0, repositorySaltFromFile.Length);

                            // Устанавливаем соль репозитория через метод
                            _userRepository.SetRepositorySalt(repositorySaltFromFile);

                            _userRepository.SetRepositoryIv(_iv);
                            // Генерируем ключ на основе парольной фразы и соли репозитория
                            _key = _cryptoService.GenerateKey(passphrase, repositorySaltFromFile);
                        }

                        // Записываем соль и IV в отдельный файл для отладки
                        _userRepository.WriteSaltAndIV("salt_iv.txt");

                        // Загружаем пользователей
                        _userRepository.LoadUsers(_key, _iv);

                        // Проверяем наличие учетной записи администратора
                        if (_userRepository.GetUser("ADMIN") == null)
                        {
                            throw new Exception("Учетная запись администратора не найдена.");
                        }

                        return true;
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Ошибка при загрузке данных: " + ex.Message, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                        return false;
                    }
                }
            }
            return false;
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameTextBox.Text.Trim();
            string password = PasswordBox.Password;

            /*if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                ErrorMessageTextBlock.Text = "Пожалуйста, введите имя пользователя и пароль.";
                return;
            }*/

            var user = _userRepository.GetUser(username);
            if (user == null)
            {
                ErrorMessageTextBlock.Text = "Пользователь не найден.";
                return;
            }

            if (user.IsBlocked)
            {
                ErrorMessageTextBlock.Text = "Учетная запись заблокирована. Обратитесь к администратору.";
                return;
            }

            // Проверяем пароль
            var hashedPassword = _cryptoService.HashPassword(password, user.Salt);
            if (hashedPassword.SequenceEqual(user.PasswordHash))
            {
                // Аутентификация успешна
                ErrorMessageTextBlock.Text = "";

                // Открываем соответствующее окно
                if (user.Username.Equals("ADMIN", StringComparison.OrdinalIgnoreCase))
                {
                    var adminWindow = new AdminWindow(_userRepository, _cryptoService, _key, _iv);
                    adminWindow.Show();
                }
                else
                {
                    var userWindow = new UserWindow(user, _userRepository, _cryptoService, _key, _iv);
                    userWindow.Show();
                }

                this.Close();
            }
            else
            {
                _loginAttempts++;
                if (_loginAttempts >= MaxLoginAttempts)
                {
                    MessageBox.Show("Превышено количество попыток ввода пароля. Программа будет закрыта.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                    Application.Current.Shutdown();
                }
                else
                {
                    ErrorMessageTextBlock.Text = $"Неправильный пароль. Осталось попыток: {MaxLoginAttempts - _loginAttempts}";
                    PasswordBox.Clear();
                }
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }
}
