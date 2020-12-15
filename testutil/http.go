package testutil

import (
	"net/http"
	"net/http/httptest"
)

func NewHttpTestServer(response []byte, httpStatus int) *httptest.Server {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if httpStatus == 0 {
			httpStatus = http.StatusOK
		}
		res.WriteHeader(httpStatus)
		//nolint
		res.Write([]byte(response))
	}))
	return testServer
}
