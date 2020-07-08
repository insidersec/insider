package visitor

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

// A result is the product of reading and summing a file using MD5.
type result struct {
	path string
	data []byte
	err  error
}

// sumFiles starts goroutines to walk the directory tree at root and digest each
// regular file.  These goroutines send the results of the digests on the result
// channel and send the result of the walk on the error channel.  If done is
// closed, sumFiles abandons its work.
func sumFiles(done <-chan struct{}, root string) (<-chan result, <-chan error) {
	// For each regular file, start a goroutine that sums the file and sends
	// the result on resultChannel.  Send the result of the walk on errc.
	resultChannel := make(chan result)
	errc := make(chan error, 1)
	go func() {
		var wg sync.WaitGroup
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			wg.Add(1)
			go func() {
				data, err := ioutil.ReadFile(path)
				select {
				case resultChannel <- result{path, data, err}:
				case <-done:
				}
				wg.Done()
			}()

			// Abort the walk if done is closed.
			select {
			case <-done:
				return errors.New("Walk canceled")
			default:
				return nil
			}
		})

		// Walk has returned, so all calls to wg.Add are done.  Start a
		// goroutine to close resultChannel once all the sends are done.
		go func() {
			wg.Wait()
			close(resultChannel)
		}()
		// No select needed here, since errc is buffered.
		errc <- err
	}()
	return resultChannel, errc
}

// DigestFile returns the MD5, SHA1 and SHA256 digests for the given file
func DigestFile(filename string) (md5Digest string, sha1Digest string, sha256Digest string, err error) {
	data, err := ioutil.ReadFile(filename)

	if err != nil {
		return
	}

	md5Hash := md5.Sum(data)
	sha1Hash := sha1.Sum(data)
	sha256Hash := sha256.Sum256(data)

	md5Digest = fmt.Sprintf("%x", md5Hash)
	sha1Digest = fmt.Sprintf("%x", sha1Hash)
	sha256Digest = fmt.Sprintf("%x", sha256Hash)

	return
}

// DigestDirectory reads all the files in the file tree rooted at dirname and returns a map
// from file path to the MD5 sum of the file's contents.  If the directory walk
// fails or any read operation fails, DigestDirectory returns an error.  In that case,
// DigestDirectory does not wait for inflight read operations to complete.
func DigestDirectory(dirname string) (
	md5FinalDigest string,
	sha1FinalDigest string,
	sha256FinalDigest string,
	err error,
) {
	// DigestDirectory closes the done channel when it returns; it may do so before
	// receiving all the values from resultChannel and errc.
	done := make(chan struct{})
	defer close(done)

	resultChannel, errc := sumFiles(done, dirname)

	directoryData := make([]byte, 0)

	for r := range resultChannel {
		if r.err != nil {
			return "", "", "", r.err
		}

		directoryData = append(directoryData, r.data...)
	}

	finalMD5 := md5.Sum(directoryData)
	finalSHA1 := sha1.Sum(directoryData)
	finalSHA256 := sha256.Sum256(directoryData)

	md5FinalDigest = fmt.Sprintf("%x", finalMD5)
	sha1FinalDigest = fmt.Sprintf("%x", finalSHA1)
	sha256FinalDigest = fmt.Sprintf("%x", finalSHA256)

	if err := <-errc; err != nil {
		return "", "", "", err
	}

	return md5FinalDigest, sha1FinalDigest, sha256FinalDigest, nil
}
