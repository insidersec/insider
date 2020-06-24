package visitor

import (
	"testing"
)

func TestDigestDirectory(t *testing.T) {
	dirname := SolvePathToTestFolder("encoding")

	md5, sha1, sha256, err := DigestDirectory(dirname)

	if err != nil {
		t.Fatal(err.Error())
	}

	if md5 == "" || sha1 == "" || sha256 == "" {
		t.Fatal("Should have digested the directory.")
	}

	t.Logf("MD5: %s", md5)
	t.Logf("SHA1: %s", sha1)
	t.Logf("SHA256: %s", sha256)
}
