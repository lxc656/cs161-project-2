package client

// CS 161 Project 2
// Authors: Ethan Song (email: esong200@berkeley.edu, SID: 3036030256), Jake Kim (email: jake.kim114@berkeley.edu, SID: 3034926636)

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
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

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
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

//Struct used to represnet a file header, stored in DataStore along with users
type FileHeader struct {
	Owner     string   //Owner of the file
	Filename  string   //filenamed
	Page_list []string //list of uuids that each point to pages of the file

	SE_key_page   []byte //16 byte symmetric key
	HMAC_key_page []byte
}

//Page struct, a bunch of these are gathered together to form a full file
type Page struct {
	Text []byte //text of a page, limited to 256 bytes
}

//Invitations struct, the location of an invitation struct is sent to another user to share files
type Invitation struct {
	File_uuid            uuid.UUID //location of the shared file
	Sender_username      string
	Recipient_username   string
	SE_Key_Invitation    []byte    //symmetric key used to access the file's keys
	HMAC_Key_Invitation  []byte    //hmac key used to access the file's keys
	Invitation_keys_uuid uuid.UUID //location of the actual file's keys
}

//Where the invitation struct points to
type FileKey struct {
	SE_Key_File   []byte
	HMAC_Key_File []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//Check if empty username
	if len(username) == 0 {
		return nil, fmt.Errorf("Empty username error")
	}

	//Check if user already exists
	user_hash := userlib.Hash([]byte(username))[0:16]
	user_uuid, uuid_err := uuid.FromBytes(user_hash)
	if uuid_err != nil {
		fmt.Println("Error")
	}
	user_struct, ok := userlib.DatastoreGet(user_uuid)
	_ = user_struct

	if ok { //if the user already exists
		return nil, fmt.Errorf("User already exists!")
	}
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

	user_uuid, err_user_uuid := uuid.FromBytes(userlib.Hash([]byte(new_user.Username + "0")))
	if err_user_uuid != nil {
		return nil, fmt.Errorf("Error generating user UUID: %v", err_user_uuid)
	}
	user_hmac_uuid, err_user_hmac_uuid := uuid.FromBytes(userlib.Hash([]byte(new_user.Username + "1")))
	if err_user_hmac_uuid != nil {
		return nil, fmt.Errorf("Error generating user's hmac UUID: %v", user_hmac_uuid)
	}

	// Serialize new user
	marshalled_user, err_marshal := json.Marshal(new_user)
	if err_marshal != nil {
		return nil, fmt.Errorf("Error serializing: %v", err_marshal)
	}

	// Encrypy new user
	SE_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(new_user.Username+"0")), 16)
	encrypted_user := userlib.SymEnc(SE_Key_User, userlib.RandomBytes(16), marshalled_user)

	// compute HMAC tag for new user
	HMAC_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(new_user.Username+"1")), 16)
	HMAC_tag_user, hmac_error := userlib.HMACEval(HMAC_Key_User, encrypted_user)
	_ = hmac_error

	// Add new user and their hmac tag to datastore
	userlib.DatastoreSet(user_uuid, encrypted_user)
	userlib.DatastoreSet(user_hmac_uuid, HMAC_tag_user)

	return &new_user, nil
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

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
