package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSomething(t *testing.T) {

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/hello", nil)

	mainHandler(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
}
