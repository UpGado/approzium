package util

import (
	"fmt"
	"io/ioutil"
)

// ReadFile exists because sometimes ioutil.ReadFile returns both
// a "file name too long" error, and the actual body of the file.
// We only want to worry about the error if the file can't be read.
func ReadFile(filename string) ([]byte, error) {
	fmt.Println("I got here")
	fmt.Println("Reading " + filename)
	result, err := ioutil.ReadFile(filename)
	fmt.Printf("result is %s", result)
	fmt.Printf("err is %s", err)
	if fmt.Sprintf("%s", result) == "" && err != nil {
		return nil, err
	}
	return result, nil
}
