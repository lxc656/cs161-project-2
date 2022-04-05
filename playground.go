//Playground
//Authors: Ethan Song (email: esong200@berkeley.edu, SID: 3036030256), Jake Kim (email: jake.kim114@berkeley.edu, SID: 3034926636)

//File used to test golang implementations
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

type User struct {
	Username    string
	PKE_Private userlib.PKEDecKey //User's private key to be used in RSA Encryption
	DS_Private  userlib.DSSignKey //User's private digital signature key to be used for verification, 16 bytes

	//key: file uuid, value: [SE_Key_File, HMAC_Key_File]
	Files_owned map[uuid.UUID][2]string

	//key: file uuid, value: list of invitation IDs for each file
	Invitation_list map[uuid.UUID][]string

	//key: file uuid, value: list of invitation IDs for each file
	Shared_files map[uuid.UUID][]string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

/*func InitUser(username string, password string) (userdataptr *User, err error) {
	//Check if user already exists
	user_hash := userlib.Hash([]byte(username))[0:16]
	user_uuid, err := uuid.FromBytes(user_hash)
	if err != nil {
		fmt.Println("Error")
	}
	user_struct, ok := userlib.DatastoreGet(user_uuid)

	if ok { //if user doesn't exist, create a new user struct

		//Generate and store pke private and public keys
		pke_public, pke_private, err_pke_keygen := userlib.PKEKeyGen()
		userlib.KeystoreSet(string(userlib.Hash([]byte(username+"3"))), pke_public)

		//Generate and store ds keys
		ds_sign_key, ds_verify_key, err_ds_keygen := userlib.DSKeyGen()
		new_user := User{
			Username:    username,
			PKE_Private: pke_private,
			DS_Private:  ds_sign_key,
		}

		//Add new user to datastore

	} else { //is the user does already exist

	}
}*/

func main() {
	fmt.Println("My favorite number is", rand.Intn(10))

	username := "esong200"
	password := "cs161"
	//Generate and store pke private and public keys
	pke_public, pke_private, err_pke_keygen := userlib.PKEKeyGen()
	_ = err_pke_keygen
	userlib.KeystoreSet(string(userlib.Hash([]byte("esong2003"))), pke_public)

	//Generate and store ds keys
	ds_sign_key, ds_verify_key, err_ds_keygen := userlib.DSKeyGen()
	_ = err_ds_keygen
	userlib.KeystoreSet(string(userlib.Hash([]byte("esong2004"))), ds_verify_key)

	//Create new user struct
	new_user := User{
		Username:    username,
		PKE_Private: pke_private,
		DS_Private:  ds_sign_key,
	}
	fmt.Println(userlib.KeystoreGet(string(userlib.Hash([]byte(new_user.Username + "3")))))

	marshalled_user, err := json.Marshal(new_user)
	_ = err

	user_uuid, err_uuid := uuid.FromBytes(userlib.Hash([]byte(new_user.Username)))
	_ = err_uuid

	SE_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(new_user.Username+"0")), 16)
	HMAC_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(new_user.Username+"1")), 16)

	encrypted_user := userlib.SymEnc(SE_Key_User, userlib.RandomBytes(16), marshalled_user)
	HMACed_user, hmac_error := userlib.HMACEval(HMAC_Key_User, encrypted_user)
	_ = hmac_error

	userlib.DatastoreSet(user_uuid, HMACed_user)

	//Test HMAC by modifying user struct entry in datastore
	modified_entry := append(userlib.DatastoreGet(user_uuid), 'a')
	userlib.DatastoreSet(user_uuid, auserlib.DatastoreGet(user_uuid))

	fmt.Print(userlib.DatastoreGet(user_uuid))

}
