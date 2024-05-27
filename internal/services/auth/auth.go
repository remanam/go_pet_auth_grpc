package auth

import (
	"auth_grpc/internal/domain/models"
	"auth_grpc/internal/lib/logger/sl"
	"auth_grpc/internal/storage"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"auth_grpc/internal/lib/jwt"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserStorage interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
	GetUser(ctx context.Context, email string) (models.User, error)
}

// интерфейс для получения App из хранилища:
type AppProvider interface {
	GetAppInfo(ctx context.Context, appID int) (models.App, error)
}

type Auth struct {
	log         *slog.Logger
	userStorage UserStorage
	appProvider AppProvider
	tokenTTL    time.Duration
}

func New(
	log *slog.Logger,
	userStorage UserStorage,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		userStorage: userStorage,
		log:         log,
		appProvider: appProvider,
		tokenTTL:    tokenTTL, // Время жизни возвращаемых токенов
	}
}

// RegisterNewUser registers new user in the system and returns user ID.
// If user with given username already exists, returns error.
func (a *Auth) RegisterNewUser(ctx context.Context, email string, pass string) (int64, error) {

	// op (operation) - имя текущей функции и пакета. Такую метку удобно
	// добавлять в логи и в текст ошибок, чтобы легче было искать хвосты
	// в случае поломок.
	const op = "Auth.RegisterNewUser"

	// Создаём локальный объект логгера с доп. полями, содержащими полезную инфу
	// о текущем вызове функции
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	// Генерируем хэш и соль для пароля.
	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	// Сохраняем пользователя в БД
	id, err := a.userStorage.SaveUser(ctx, email, passHash)
	if err != nil {
		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// Login checks if user with given credentials exists in the system and returns access token.
//
// If user exists, but password is incorrect, returns error.
// If user doesn't exist, returns error.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string, // пароль в чистом виде, аккуратней с логами!
	appID int, // ID приложения, в котором логинится пользователь
) (string, error) {
	const op = "Auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
		// password либо не логируем, либо логируем в замаскированном виде
	)

	log.Info("attempting to login user")

	// Достаём пользователя из БД
	user, err := a.userStorage.GetUser(ctx, email)
	if err != nil {
		if err == storage.ErrUserNotFound {
			a.log.Warn("user not found", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	// Проверяем корректность полученного пароля
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	// Получаем информацию о приложении
	app, err := a.appProvider.GetAppInfo(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	// Создаём токен авторизации
	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}
