package storage

import "errors"

var (
	ErrBlobNotFound = errors.New("blob not found")
	ErrInvalidID    = errors.New("invalid blob id")
	ErrEmptyPayload = errors.New("cannot store empty payload")
)
