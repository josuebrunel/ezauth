package models

// ColumnValue is a column name and the text to write to it.
type ColumnValue struct {
	Column string
	Value  string
}

// ProfileColumns are the user columns Repository.UserUpdateProfile may write.
// It is a fixed allowlist because the column names go into the SQL text.
var ProfileColumns = map[string]bool{
	ColumnFirstName: true,
	ColumnLastName:  true,
	ColumnUsername:  true,
	ColumnPhone:     true,
	ColumnLocale:    true,
	ColumnTimezone:  true,
	ColumnAvatarURL: true,
	ColumnNickname:  true,
}
