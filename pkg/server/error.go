package server

type MappingError struct {
	err error
}

func NewMappingError(err error) MappingError {
	return MappingError{err: err}
}

func (m MappingError) Error() string {
	return m.err.Error()
}
