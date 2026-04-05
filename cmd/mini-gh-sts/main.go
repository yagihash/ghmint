package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fmt.Println("hello")
	return 0
}
