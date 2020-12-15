package testutil

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func NewTestLogger(t testing.TB) *log.Logger {
	if v := os.Getenv("INSIDER_TEST_DEBUG"); len(v) != 0 {
		return log.New(os.Stderr, "", 0)
	}

	return log.New(ioutil.Discard, "", 0)
}
