package util

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func Deref[T any](t *T) T {
	if t == nil {
		var zero T
		return zero
	}
	return *t
}
