package util

import "io/ioutil"

// ReadFile exists because sometimes ioutil.ReadFile returns both
// a "file name too long" error, and the actual body of the file.
// We only want to worry about the error if the file can't be read.
func ReadFile(filename string) ([]byte, error) {
	result, err := ioutil.ReadFile(filename)
	if len(result) == 0 && err != nil {
		return nil, err
	}
	return result, nil
}
