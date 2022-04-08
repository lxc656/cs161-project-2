//Authors: Ethan Song (email: esong200@berkeley.edu, SID: 3036030256), Jake Kim (email: jake.kim114@berkeley.edu, SID: 3034926636)

//File used to test golang implementations
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

type User struct {
	Username    string
	Password    string            // Only used to pull updates from datastore
	PKE_Private userlib.PKEDecKey //User's private key to be used in RSA Encryption
	DS_Private  userlib.DSSignKey //User's private digital signature key to be used for verification, 16 bytes

	//key: file uuid, value: [SE_Key_File, HMAC_Key_File]
	Files_owned map[uuid.UUID][2]string

	//key: file uuid, value: list of invitation IDs for each file
	Invitation_list map[uuid.UUID][]string

	//key: filename, value: invitation ID recived for a particular file
	Shared_files map[uuid.UUID]uuid.UUID

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

//Struct used to represnet a file header, stored in DataStore along with users
type FileHeader struct {
	Owner         string         // Owner of the file
	Filename      string         // filenamed
	Page_list     [][2]uuid.UUID // list of uuid pairs (one points to page, other points to hmac tag)
	SE_key_page   []byte         // 16 byte symmetric key
	HMAC_key_page []byte         // 16 byte HMAC key
}

//Page struct, a bunch of these are gathered together to form a full file
type Page struct {
	Text []byte //text of a page, limited to 256 bytes
}

//function for generating a new random uuid that has not been taken yet
func generate_new_uuid() (random_uuid uuid.UUID) {
	new_uuid := uuid.New()
	item, ok := userlib.DatastoreGet(new_uuid)
	_ = item
	for ok { //while the uuid is taken in datastore, generate a new uuid
		new_uuid = uuid.New()
		item, ok = userlib.DatastoreGet(new_uuid)
		_ = item
	}
	return new_uuid
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
			Username:        username,
			PKE_Private:     pke_private,
			DS_Private:      ds_sign_key,
			Files_owned:     make(map[uuid.UUID][2]string),
			Invitation_list: make(map[uuid.UUID][]string),
			Shared_files:    make(map[uuid.UUID]uuid.UUID),
		}

		// Serialize new user
		marshaled_user, err_marshal := json.Marshal(new_user)
		if err_marshal != nil {
			return nil, fmt.Errorf("Error serializing: %v", err_marshal)
		}

		//Generate uuid for HMAC tag
		user_hmac_uuid, err_user_hmac_uuid := uuid.FromBytes(userlib.Hash([]byte(new_user.Username + "1"))[0:16])
		if err_user_hmac_uuid != nil {
			return nil, fmt.Errorf("Error generating user's hmac UUID: %v", user_hmac_uuid)
		}

		// Encrypy new user
		SE_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(new_user.Username+"0")), 16)
		encrypted_user := userlib.SymEnc(SE_Key_User, userlib.RandomBytes(16), marshaled_user)

		// Generate HMAC tag
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

	var unmarshaled_user User //User struct to be returned
	if unmarshal_err := json.Unmarshal(decrypted_user, &unmarshaled_user); unmarshal_err != nil {
		return nil, fmt.Errorf("Error unmarshaling user struct: %v", unmarshal_err)
	}

	//return decrypted user struct
	return &unmarshaled_user, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//Before anything, CHECK FOR UPDATES IN DATASTORE (for multiple sessions, in case another session makes an update)
	updated_user_data, get_user_err := GetUser(userdata.Username, userdata.Password)
	if get_user_err != nil { // If somehow the user isn't in datastore, definitely an error lol
		fmt.Errorf(get_user_err.Error())
	}

	//From now on, use updated_user_data for file storage

	//Generate uuid for file
	file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + updated_user_data.Username))[:16])
	if file_uuid_err != nil {
		return file_uuid_err
	}

	/*DEPRECIATED, DOESN'T MATTER IF FILE EXISTS ALREADY OR NOT
	----------------------------------------------------
	//Check if file with same name already exists
	retrieved_file, ok := userlib.DatastoreGet(file_uuid)
	if ok { // if the file already exists, overwrite

	}
	*/

	//Generate random SE and HMAC keys that will be used for all file pages
	se_key_page := userlib.RandomBytes(16)
	hmac_key_page := userlib.RandomBytes(16)

	//Create new file header
	file_header := FileHeader{
		Owner:         updated_user_data.Username,
		Filename:      filename,
		Page_list:     make([][2]uuid.UUID, 0), // List of page UUIDs, in order
		SE_key_page:   se_key_page,
		HMAC_key_page: hmac_key_page,
	}
	// Split content into pages, each 256 bytes
	for i := 0; i < len(content); i++ {
		if i%256 == 0 {
			var new_page Page
			if i+256 <= len(content) {
				new_page = Page{
					Text: content[i : i+256],
				}
			} else {
				new_page = Page{
					Text: content[i:],
				}
				break
			}
			// Marshal each page
			marshaled_page, err_marshal := json.Marshal(new_page)
			if err_marshal != nil {
				return fmt.Errorf("Error serializing file page: %v", err_marshal)
			}

			//Generate uuid for page and HMAC tag
			page_hmac_uuid := generate_new_uuid()
			page_uuid := generate_new_uuid()

			// Encrypt and create HMAC tag for each page
			encrypted_page := userlib.SymEnc(file_header.SE_key_page, userlib.RandomBytes(16), marshaled_page)
			hmac_tag_page, hmac_error := userlib.HMACEval(hmac_key_page, encrypted_page)
			_ = hmac_error

			// Store encrypted page and hmac tag in datastore
			userlib.DatastoreSet(page_uuid, encrypted_page)
			userlib.DatastoreSet(page_hmac_uuid, hmac_tag_page)

			// Update File Header
			var to_append = [2]userlib.UUID{page_uuid, page_hmac_uuid}
			file_header.Page_list = append(file_header.Page_list, to_append)
		}
	}

	//marshal file
	file_header_marshaled, file_marshal_err := json.Marshal(content)
	if err != nil {
		return file_marshal_err
	}

	//Encrypt file

	userlib.DatastoreSet(storageKey, content_marshaled)
	return
}

// func (userdata *User) LoadFile(filename string) (content []byte, err error)  {
// 	updated_user_data, get_user_err := GetUser(userdata.Username, userdata.Password)
// 	if get_user_err != nil {// If somehow the user isn't in datastore, definitely an error lol
// 		fmt.Errorf(get_user_err.Error())
// 	}
// 	file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
// 	if file_uuid_err != nil {
// 		return file_uuid_err
// 	}
// 	for key, element := range updated_user_data.Shared_files {
// 		if key == filename:
// 			file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
//     }

// }
func (userdata *User) ChangeUsername(new_username string) {
	userdata.Username = new_username
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
	retrieved_user_web, get_user_err := GetUser(username, password)
	//retrieved_user_phone, get_user_err_2 := GetUser(username, password)
	if get_user_err != nil {
		panic(get_user_err)
	}
	_ = retrieved_user_web

	var test_arr [2]string

	test_arr[0] = "Hello"
	test_arr[1] = "World"

	retrieved_user_web.Files_owned[uuid.New()] = test_arr
	retrieved_user_web.ChangeUsername("NewUsername")

	fmt.Println("Retrieved_User_Web Address:", retrieved_user_web)
	//Test File Storage
}
