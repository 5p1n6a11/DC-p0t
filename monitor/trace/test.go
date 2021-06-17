// env GOOS=linux GOARCH=amd64 go build test.go
// objdump -t test | grep sleep

package main

import (
    "fmt"
    "time"
)

func main() {
    fmt.Println("Hello")
    sleep()
}

func sleep() {
    time.Sleep(30 * time.Second)
}

