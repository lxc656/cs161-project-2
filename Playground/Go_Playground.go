package Playground

import (
	"fmt"
)

func main() {
	a := make(map[string][2]string)
	var test_arr [2]string
	a["Hello"] = test_arr
	fmt.Print(a)
}
