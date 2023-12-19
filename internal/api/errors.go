package api

import (
	"context"
	"fmt"
	"net/http"
)

type HTTPError struct {
	Code            int    `json:"code"`
	Message         string `json:"msg"`
	InternalError   error  `json:"-"`
	InternalMessage string `json:"-"`
	ErrorID         string `json:"error_id,omitempty"`
}

func (e *HTTPError) Error() string {
	if e.InternalMessage != "" {
		return e.InternalMessage
	}
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func (e *HTTPError) Is(target error) bool {
	return e.Error() == target.Error()
}

// Cause returns the root cause error
func (e *HTTPError) Cause() error {
	if e.InternalError != nil {
		return e.InternalError
	}
	return e
}

// WithInternalError adds internal error information to the error
func (e *HTTPError) WithInternalError(err error) *HTTPError {
	e.InternalError = err
	return e
}

// WithInternalMessage adds internal message information to the error
func (e *HTTPError) WithInternalMessage(fmtString string, args ...interface{}) *HTTPError {
	e.InternalMessage = fmt.Sprintf(fmtString, args...)
	return e
}

func httpError(code int, fmtString string, args ...interface{}) *HTTPError {
	return &HTTPError{
		Code:    code,
		Message: fmt.Sprintf(fmtString, args...),
	}
}

func handleError(err error, w http.ResponseWriter, r *http.Request) {}

func recoverer(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	defer func() {
		if rvr := recover(); rvr != nil {

			//logEntry := observability.GetLogEntry(r)
			//if logEntry != nil {
			//	logEntry.Panic(rvr, debug.Stack())
			//} else {
			//	fmt.Fprintf(os.Stderr, "Panic: %+v\n", rvr)
			//	debug.PrintStack()
			//}

			se := &HTTPError{
				Code:    http.StatusInternalServerError,
				Message: http.StatusText(http.StatusInternalServerError),
			}
			handleError(se, w, r)
		}
	}()

	return nil, nil
}

func badRequestError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusBadRequest, fmtString, args...)
}
