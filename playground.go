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

func InitUser(username string, password string) (userdataptr *User, err error) {
	//Check if empty username
	if len(username) == 0 {
		return nil, fmt.Errorf("Empty username error")
	}

	//Check if user already exists
	user_hash := userlib.Hash([]byte(username))[0:16]
	user_uuid, uuid_err := uuid.FromBytes(user_hash)
	if uuid_err != nil {
		fmt.Errorf("UUID Error:%v", uuid_err)
	}
	user_struct, ok := userlib.DatastoreGet(user_uuid)
	_ = user_struct

	if !ok { // if user doesn't exist, create a new user struct
		// Generate and store pke private and public keys
		pke_public, pke_private, err_pke_keygen := userlib.PKEKeyGen()
		if err_pke_keygen != nil {
			return nil, fmt.Errorf("Error generating PKE key: %v", err_pke_keygen)
		}
		userlib.KeystoreSet(string(userlib.Hash([]byte(username+"0"))), pke_public)

		// Generate and store ds keys
		ds_sign_key, ds_verify_key, err_ds_keygen := userlib.DSKeyGen()
		if err_ds_keygen != nil {
			return nil, fmt.Errorf("Error generating DS key: %v", err_ds_keygen)
		}
		userlib.KeystoreSet(string(userlib.Hash([]byte(username+"1"))), ds_verify_key)

		new_user := User{
			Username:    username,
			PKE_Private: pke_private,
			DS_Private:  ds_sign_key,
		}

		//Generate and store HMAC tag
		user_hmac_uuid, err_user_hmac_uuid := uuid.FromBytes(userlib.Hash([]byte(new_user.Username + "1"))[0:16])
		if err_user_hmac_uuid != nil {
			return nil, fmt.Errorf("Error generating user's hmac UUID: %v", user_hmac_uuid)
		}

		// Serialize new user
		marshaled_user, err_marshal := json.Marshal(new_user)
		if err_marshal != nil {
			return nil, fmt.Errorf("Error serializing: %v", err_marshal)
		}

		// Encrypy new user
		SE_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(new_user.Username+"0")), 16)
		encrypted_user := userlib.SymEnc(SE_Key_User, userlib.RandomBytes(16), marshaled_user)

		// HMAC new user
		HMAC_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(new_user.Username+"1")), 16)
		HMAC_tag_user, hmac_error := userlib.HMACEval(HMAC_Key_User, encrypted_user)
		_ = hmac_error

		// Add new encrypted user struct and their HMAC to datastore
		userlib.DatastoreSet(user_uuid, encrypted_user)
		userlib.DatastoreSet(user_hmac_uuid, HMAC_tag_user)

		return &new_user, nil

	} else { //if the user already exists
		return nil, fmt.Errorf("User already exists!")
	}
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	//Check if user exists
	user_hash := userlib.Hash([]byte(username))[0:16]
	user_uuid, uuid_err := uuid.FromBytes(user_hash)
	if uuid_err != nil {
		fmt.Errorf("UUID Error:%v", uuid_err)
	}
	user_struct, ok := userlib.DatastoreGet(user_uuid)
	if !ok { // If user is not found in datastore
		return nil, fmt.Errorf("User doesn't exist in datastore:")
	}
	//Obtain keys determistically from provided username and password
	SE_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username+"0")), 16)
	HMAC_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username+"1")), 16)

	//Verify HMAC
	stored_hmac_uuid, uuid_hmac_err := uuid.FromBytes(userlib.Hash([]byte(username + "1"))[0:16])
	if uuid_hmac_err != nil {
		return nil, fmt.Errorf("Error generating hmac uuid: %v", uuid_hmac_err)
	}
	stored_hmac_tag, hmac_ok := userlib.DatastoreGet(stored_hmac_uuid)
	_ = hmac_ok
	computed_hmac_tag, computed_hmac_error := userlib.HMACEval(HMAC_Key_User, user_struct)
	_ = computed_hmac_error

	if !(userlib.HMACEqual(stored_hmac_tag, computed_hmac_tag)) {
		return nil, fmt.Errorf("Warning: User struct has been tampered with!")
	}

	//Decrypt user
	decrypted_user := userlib.SymDec(SE_Key_User, user_struct)

	var unmarshaled_user User
	if unmarshal_err := json.Unmarshal(decrypted_user, &unmarshaled_user); unmarshal_err != nil {
		return nil, fmt.Errorf("Error unmarshaling user struct: %v", unmarshal_err)
	}

	//return decrypted user struct
	return &unmarshaled_user, nil
}

func main() {
	fmt.Println("My favorite number is", rand.Intn(10))

	username := "esong200"
	password := "cs161"

	user, err := InitUser(username, password)
	_ = user
	//fmt.Println("User pointer:", user)
	fmt.Println("Error:", err)

	//Test GetUser
	retrieved_user, get_user_err := GetUser(username, password)
	_ = get_user_err
	_ = retrieved_user
	fmt.Println("Retrieved_User:", retrieved_user)
	fmt.Println("Error:", get_user_err)
}
