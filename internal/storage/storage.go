package storage

import "errors"

//В основном пакете storage я храню лишь общие описания типов, ошибок и т.п. В моём текущем случае — это только ошибки:

// По этим ошибкам сервисный слой сможет понять, что конкретно пошло не так, и принимать соответствующие решения.
// Они не должны зависеть от конкретной реализации хранилища (будь то SQLite, Postgres, MongoDB и т.п.), поэтому мы их разместили в общем пакете.
var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
	ErrAppNotFound  = errors.New("app not found")
)
