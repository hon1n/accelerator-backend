package repository

import (
	"accelerator/internal/core/error_type"
	"accelerator/internal/domains"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// создаем интейрфейс, который удовлетворяет и pgxpool.Pool и tx
// чтобы потом в методах репозитория не зависеть только от типа pool и чтобы можно было выполнять методы и через tx
type executor interface { 
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// передаем экземпляр на пул подключений, чтобы потом юзать методы через единый экземпляр и не передавать постоянно его в функции
type AuthRepo struct {
	pool *pgxpool.Pool
}

// конструктор репозитория, вызываем в main
func NewAuthRepo(pool *pgxpool.Pool) *AuthRepo {
	return &AuthRepo{
		pool: pool,
	}
}

// по сути конструтор для создания транзакции, так как сервис не может иметь напрямую доступ к repo.pool
// то создаем транзакцию через pool здесь, а в сервисе только используем методы транзакций
func (repo *AuthRepo) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	return repo.pool.BeginTx(ctx, opts)
}

// АНОНИМНАЯ ФУНКЦИЯ ДЛЯ РАБОТЫ ЧЕРЕЗ ИНТЕРФЕЙС ПОДКЛЮЧЕНИЯ
// принимает хеш, уникальный ключ токена, время создания и время исхода рефреш токена
// создает новую сессию в бд
// возвращает ошибки
func (repo *AuthRepo) createSession(
		ctx context.Context, 
		e executor, 
		userID, refreshHash, RefreshJTI string, 
		refreshCreate, refreshExpire time.Time,
	) error {
	sqlQuery := `
	INSERT INTO sessions (user_id, token_hash, jti, created_at, expires_at) 
	VALUES ($1, $2, $3, $4, $5);
	`
	_, err := e.Exec(ctx, sqlQuery, userID, refreshHash, RefreshJTI, refreshCreate, refreshExpire) // тоже самое, унивесальная функция
	if err != nil {
		return error_type.NewInternal(fmt.Errorf("create session: %w", err))
	}

	return nil
}

// публичные обертки
func (repo *AuthRepo) CreateSession(
		ctx context.Context, 
		userID, refreshHash, RefreshJTI string, 
		refreshCreate, refreshExpire time.Time,
	) error {
	return repo.createSession(ctx, repo.pool, userID, refreshHash, RefreshJTI, refreshCreate, refreshExpire)
}

func (repo *AuthRepo) CreateSessionTx(
		ctx context.Context, 
		tx pgx.Tx,  
		userID, refreshHash, RefreshJTI string, 
		refreshCreate, refreshExpire time.Time,
	) error {
	return repo.createSession(ctx, tx, userID, refreshHash, RefreshJTI, refreshCreate, refreshExpire)
}



// ДЛЯ ОБЫЧНЫХ SELECT ЗАПРОСОВ НЕ НУЖНЫ ТРАНЗАКЦИИ, ОНИ НЕ МЕНЯЮТ БАЗУ ДАННЫХ
// проверяет существование пользователя с такой почтой
// возвращает ошибки, полученный hash от пароля, id пользователя, роль и флаг, временный ли пароль
func (repo *AuthRepo) GetAuthCredentials(ctx context.Context, login string) (*domains.UserAuthInfo, error) {
    sqlQuery := `
        SELECT id, password_hash, role, temporary_password
        FROM users 
        WHERE login = $1;
    `
	var info domains.UserAuthInfo
    err := repo.pool.QueryRow(ctx, sqlQuery, login).Scan(
		&info.ID, 
		&info.PasswordHash,
		&info.Role,
		&info.TemporaryPassword,
	)
    if errors.Is(err, pgx.ErrNoRows) { // специальный тип ошибки, если ничего не вернулось
        return nil, error_type.NewUnauthorized("Invalid login or password") // пользователь не найден
    } else if err != nil {
        return nil, error_type.NewInternal(fmt.Errorf("get auth credentials: %w", err))
    }
    return &info, nil
}


// принимает jti рефреш токена
// получает информацию о сессии
// возвращает информацию о сессии и ошибку
func (repo *AuthRepo) GetSessionByJTI(ctx context.Context, jti string) (*domains.Session, error) {
	sqlQuery := `
	SELECT user_id, token_hash, jti, revoked_at, created_at, expires_at
	FROM sessions
	WHERE jti = $1;
	`
	var sessionInfo domains.Session // получаем информации о сессии по данному jti токена
	err := repo.pool.QueryRow(ctx, sqlQuery, jti).Scan(
		&sessionInfo.UserID, 
		&sessionInfo.TokenHash,
		&sessionInfo.TokenJTI,
		&sessionInfo.RevokedAt,
		&sessionInfo.CreatedAt,
		&sessionInfo.ExpiresAt,
	)
    if errors.Is(err, pgx.ErrNoRows) { // специальный тип ошибки, если ничего не вернулось
        return nil, error_type.NewUnauthorized("Session not found") // сессия не найдена
    } else if err != nil {
        return nil, error_type.NewInternal(fmt.Errorf("get session info: %w", err))
    }

    return &sessionInfo, nil
}

// транзакции пока не требуются для этой функции, так что не делаем оберток
// отзывает все активные сессии пользователя, устанавливая revoked_at = NOW()
// Принимает userID и ошибку при проблемах с БД
func (repo *AuthRepo) RevokeAllUserSessions(ctx context.Context, userID string) error {
    query := `
        UPDATE sessions
        SET revoked_at = NOW()
        WHERE user_id = $1 AND revoked_at IS NULL
    `
    _, err := repo.pool.Exec(ctx, query, userID)
    if err != nil {
        return error_type.NewInternal(fmt.Errorf("revoke all user sessions: %w", err))
    }
    return nil
}


// АНОНИМНАЯ ФУНКЦИЯ ДЛЯ РАБОТЫ ЧЕРЕЗ ИНТЕРФЕЙС ПОДКЛЮЧЕНИЯ
//  помечает сессию как отозванную
// Принимает jti, если сессия уже отозвана или не существует,
// возвращает error_type.NewUnauthorized
func (repo *AuthRepo) revokeSession(ctx context.Context, e executor, jti string) error {
    query := `
        UPDATE sessions
        SET revoked_at = NOW()
        WHERE jti = $1 AND revoked_at IS NULL
    `
    cmdTag, err := e.Exec(ctx, query, jti)
    if err != nil {
        return error_type.NewInternal(fmt.Errorf("revoke session by jti: %w", err))
    }
    if cmdTag.RowsAffected() == 0 { // если ничего не вернулось из exec
        return error_type.NewUnauthorized("Session not found") // сессия не найдена
    }
    return nil
}

// обертки для функции
func (repo *AuthRepo) RevokeSession(ctx context.Context, jti string) error {
	return repo.revokeSession(ctx, repo.pool, jti)
}
func (repo *AuthRepo) RevokeSessionTx(ctx context.Context, tx pgx.Tx, jti string) error {
	return repo.revokeSession(ctx, tx, jti)
}

// =========================== ИЗМЕНЕНИЕ ВРЕМЕННОГО ПАРОЛЯ ====================================

func (repo *AuthRepo) UpdateTempPassword(ctx context.Context, callerID, passwordHash string) error {
	sqlQuery := `
		UPDATE users
		SET password_hash = $1, temporary_password = FALSE
		WHERE id = $2;
	`

	cmdTag, err := repo.pool.Exec(ctx, sqlQuery, passwordHash, callerID)
    if err != nil {
        return error_type.NewInternal(fmt.Errorf("update temperary password: %w", err))
    }
    if cmdTag.RowsAffected() == 0 { // если ничего не вернулось из exec
        return error_type.NewUnauthorized("user not found") // пользователь не найден
    }
	
	return nil
}
