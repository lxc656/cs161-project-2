package main

import (
	"fmt"
	"math/rand"
)

type User struct {
	Username    string
	PKE_Private string //User's private key to be used in RSA Encryption
	DS_Private  string //User's private digital signature key to be used for verification
	filesOwned  map[string][2]string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

func main() {
	fmt.Println("My favorite number is", rand.Intn(10))
	//var map_test = map[string]int{}
	var test_list []string
	for i := 0; i < 10; i++ {
		test_list = append(test_list, "item")
	}
	test_list = append(test_list, "item1")
	fmt.Println(test_list)
	fmt.Println("Hello", 123)
}
