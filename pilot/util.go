package pilot

import (
	"io/ioutil"
	"strings"
)

// ReadFile return string list separated by separator
func ReadFile(path string, separator string) ([]string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return strings.Split(string(data), separator), nil
}


func Func2Chan(f func() error) <-chan error{
	retChan := make(chan error)
	go func(c chan error){
		err := f()
		c <- err 
	}(retChan)

	return retChan
}