//Authors: Ethan Song (email: esong200@berkeley.edu, SID: 3036030256), Jake Kim (email: jake.kim114@berkeley.edu, SID: 3034926636)

//File used to test golang implementations
package main

import (
	"encoding/json"
	"errors"
	"fmt"

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
	Files_owned map[uuid.UUID][2][]byte

	//key: file uuid, value: list of invitation IDs for each file
	Invitation_list map[uuid.UUID][]uuid.UUID

	//key: filename, value: [sender, invitation uuid (as string)]
	Shared_files map[string][2]string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

//Struct used to represnet a file header, stored in DataStore along with users
type FileHeader struct {
	Owner         string      // Owner of the file
	Filename      string      // filenamed
	Page_list     []uuid.UUID // list of uuids pointing to pages
	SE_key_page   []byte      // 16 byte symmetric key
	HMAC_key_page []byte      // 16 byte HMAC key
}

// Page struct, a bunch of these are gathered together to form a full file
type Page struct {
	Text []byte //text of a page, limited to 256 bytes
}

// Invitation structure used to access files the user does not own. Stored in datastore, encrypted with RSA.
type Invitation struct {
	FileUUID           uuid.UUID
	Sender             string // Username of sender
	Recipient          string
	SE_Key_File_Keys   []byte
	HMAC_Key_File_Keys []byte
	FileKeysUUID       uuid.UUID
}

// File keys the invitation points to. Changed when a user is revoked from sharing permissions.
type FileKeys struct {
	SE_Key_File   []byte
	HMAC_Key_File []byte
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
			Password:        password,
			PKE_Private:     pke_private,
			DS_Private:      ds_sign_key,
			Files_owned:     make(map[uuid.UUID][2][]byte),
			Invitation_list: make(map[uuid.UUID][]uuid.UUID),
			Shared_files:    make(map[string][2]string),
		}

		// Serialize new user
		marshaled_user, err_marshal := json.Marshal(new_user)
		if err_marshal != nil {
			return nil, fmt.Errorf("Error serializing: %v", err_marshal)
		}

		// Generate uuid for HMAC tag
		// Note: hmac tag location deterministically generated
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
		fmt.Errorf("UUID generation Error:%v", uuid_err)
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
	computed_hmac_tag, computed_hmac_error := userlib.HMACEval(HMAC_Key_User, user_struct)
	_ = computed_hmac_error
	_ = hmac_ok

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

// Update user attributes in the actual datastore
func UpdateUserDataInDatastore(username string, password string, updated_user_data *User) (err error) {
	//Check if user exists
	user_hash := userlib.Hash([]byte(username))[0:16]
	user_uuid, uuid_err := uuid.FromBytes(user_hash)
	if uuid_err != nil {
		fmt.Errorf("UUID generation Error:%v", uuid_err)
	}
	user_struct, ok := userlib.DatastoreGet(user_uuid)
	if !ok { // If user is not found in datastore
		return fmt.Errorf("User doesn't exist in datastore")
	}
	//Obtain keys determistically from provided username and password
	SE_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username+"0")), 16)
	HMAC_Key_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username+"1")), 16)

	//Verify HMAC
	stored_hmac_uuid, uuid_hmac_err := uuid.FromBytes(userlib.Hash([]byte(username + "1"))[0:16])
	if uuid_hmac_err != nil {
		return fmt.Errorf("Error generating hmac uuid: %v", uuid_hmac_err)
	}
	stored_hmac_tag, hmac_ok := userlib.DatastoreGet(stored_hmac_uuid)
	computed_hmac_tag, computed_hmac_error := userlib.HMACEval(HMAC_Key_User, user_struct)
	_ = computed_hmac_error
	_ = hmac_ok

	if !(userlib.HMACEqual(stored_hmac_tag, computed_hmac_tag)) {
		return fmt.Errorf("Warning: User struct has been tampered with!")
	}

	//Decrypt user
	decrypted_user := userlib.SymDec(SE_Key_User, user_struct)

	var user User //User struct to be updated
	if unmarshal_err := json.Unmarshal(decrypted_user, &user); unmarshal_err != nil {
		return fmt.Errorf("Error unmarshaling user struct: %v", unmarshal_err)
	}

	user.Files_owned = updated_user_data.Files_owned
	user.Invitation_list = updated_user_data.Invitation_list
	user.Shared_files = updated_user_data.Shared_files

	// Serialize updated user
	marshaled_user, err_marshal := json.Marshal(user)
	if err_marshal != nil {
		return fmt.Errorf("Error serializing: %v", err_marshal)
	}

	// Generate uuid for new HMAC tag
	// Note: hmac tag location deterministically generated
	user_hmac_uuid, err_user_hmac_uuid := uuid.FromBytes(userlib.Hash([]byte(user.Username + "1"))[0:16])
	if err_user_hmac_uuid != nil {
		return fmt.Errorf("Error generating uodated user's hmac UUID: %v", user_hmac_uuid)
	}

	// Encrypy new user
	SE_Key_Updated_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(user.Username+"0")), 16)
	encrypted_updated_user := userlib.SymEnc(SE_Key_Updated_User, userlib.RandomBytes(16), marshaled_user)

	// Generate HMAC tag
	HMAC_Key_Updated_User := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(user.Username+"1")), 16)
	HMAC_tag_updated_user, hmac_error := userlib.HMACEval(HMAC_Key_Updated_User, encrypted_updated_user)
	_ = hmac_error

	// Add new encrypted user struct and their HMAC to datastore
	userlib.DatastoreSet(user_uuid, encrypted_updated_user)
	userlib.DatastoreSet(user_hmac_uuid, HMAC_tag_updated_user)

	return
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//Before anything, CHECK FOR UPDATES IN DATASTORE (for multiple sessions, in case another session makes an update)
	updated_user_data, get_user_err := GetUser(userdata.Username, userdata.Password)
	if get_user_err != nil { // If somehow the user isn't in datastore, definitely an error lol
		return fmt.Errorf("Error: user info not found: %v", get_user_err.Error())
	}

	// Update attributes of userdata
	userdata.Files_owned = updated_user_data.Files_owned
	userdata.Invitation_list = updated_user_data.Invitation_list
	userdata.Shared_files = updated_user_data.Shared_files

	// Generate random SE and HMAC keys that will be used for all file pages
	se_key_page := userlib.RandomBytes(16)
	hmac_key_page := userlib.RandomBytes(16)

	//Create new file header
	file_header := FileHeader{
		Owner:         userdata.Username,
		Filename:      filename,
		Page_list:     make([]uuid.UUID, 0), // List of page UUIDs, in order
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
			}

			// Marshal each page
			marshaled_page, err_marshal := json.Marshal(new_page)
			if err_marshal != nil {
				return fmt.Errorf("Error serializing file page: %v", err_marshal)
			}

			// Generate uuid for page and HMAC tag
			page_uuid := generate_new_uuid()

			// Encrypt and create HMAC tag for each page
			encrypted_page := userlib.SymEnc(file_header.SE_key_page, userlib.RandomBytes(16), marshaled_page)
			hmac_tag_page, hmac_error := userlib.HMACEval(hmac_key_page, encrypted_page)
			_ = hmac_error

			// Append HMAC tag behind the encrypted page
			encrypted_page_tagged := append(encrypted_page, hmac_tag_page...)

			// Store encrypted page in datastore
			userlib.DatastoreSet(page_uuid, encrypted_page_tagged)

			// Add new page uuid to file header
			file_header.Page_list = append(file_header.Page_list, page_uuid)
		}
	}

	//marshal file
	file_header_marshaled, file_marshal_err := json.Marshal(file_header)
	if err != nil {
		return file_marshal_err
	}

	//Encrypt file
	se_key_file := userlib.RandomBytes(16)
	encrypted_file_header := userlib.SymEnc(se_key_file, userlib.RandomBytes(16), file_header_marshaled)

	//Generate HMAC tag for file
	hmac_key_file := userlib.RandomBytes(16)
	hmac_tag_file, hmac_error := userlib.HMACEval(hmac_key_file, encrypted_file_header)
	_ = hmac_error

	// Append hmac_tag_file behind file header
	encrypted_file_header_tagged := append(encrypted_file_header, hmac_tag_file...)

	//Generate file uuid
	file_header_uuid, file_header_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + "0"))[:16])
	if file_header_uuid_err != nil {
		return file_header_uuid_err
	}

	//Store secured information in datastore
	userlib.DatastoreSet(file_header_uuid, encrypted_file_header_tagged)

	// Update user's FilesOwned map
	userdata.Files_owned[file_header_uuid] = [2][]byte{se_key_file, hmac_key_file}
	update_user_error := UpdateUserDataInDatastore(userdata.Username, userdata.Password, userdata)
	if update_user_error != nil {
		return fmt.Errorf("Error updating user's files owned map: %v", update_user_error)
	}
	return
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Before anything, CHECK FOR UPDATES IN DATASTORE (for multiple sessions, in case another session makes an update)
	updated_user_data, get_user_err := GetUser(userdata.Username, userdata.Password)
	if get_user_err != nil { // If somehow the user isn't in datastore, definitely an error lol
		return nil, fmt.Errorf("Error: user info not found: %v", get_user_err.Error())
	}

	// Update attributes of userdata
	userdata.Files_owned = updated_user_data.Files_owned
	userdata.Invitation_list = updated_user_data.Invitation_list
	userdata.Shared_files = updated_user_data.Shared_files

	// Derive file uuid
	file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + "0"))[:16])
	if file_uuid_err != nil {
		return nil, file_uuid_err
	}

	// First, check datastore if given user's filename exists
	encrypted_file_tagged, file_exists_in_datastore := userlib.DatastoreGet(file_uuid)
	if !file_exists_in_datastore { // If user is not found in datastore
		return nil, fmt.Errorf("File doesn't exist in datastore:")
	}
	var se_key_file []byte
	var hmac_key_file []byte

	// Then, check if user owns the file
	if file_keys, user_owns_file := userdata.Files_owned[file_uuid]; user_owns_file { // if the user owns the file
		//obtain file keys from Files_owned map
		se_key_file = file_keys[0]
		hmac_key_file = file_keys[1]

	} else { //The file is shared with the user (user does not own the file), and the user will have to access the file via invitation
		// To do: Obtain sender Shared_files, then update invitation (incase of revoked user)
		// Then access file through invitation information
		invitation_uuid, parse_err := uuid.Parse(userdata.Shared_files[filename][1]) //Note: uuid in this case stored as a string
		if parse_err != nil {
			return nil, fmt.Errorf("Error parsing uuid: %v", parse_err)
		}
		sender := userdata.Shared_files[filename][0]

		// When calling acceptInvitation to update the invitation, in this case, if the filename already exists in the user's files_shared namespace, don't error
		// This makes the same invitation_uuid point to the UPDATED invitation with updated keys
		userdata.AcceptInvitation(sender, invitation_uuid, filename)

		// Obtain invitation: The last 256 bytes of the encrypted marshaled invitation will be the DS
		signed_encrypted_invitation, ok := userlib.DatastoreGet(invitation_uuid)
		if !ok {
			return nil, fmt.Errorf("Error obtaining invitation from datastore")
		}
		encrypted_invitation := signed_encrypted_invitation[0 : len(signed_encrypted_invitation)-256]
		ds_signature := signed_encrypted_invitation[len(signed_encrypted_invitation)-256:]

		// verify invitation
		// DS signature will be at the end of the encrypted marshaled invitation
		sender_public_ds_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(sender + "1"))))
		if !ok {
			return nil, fmt.Errorf("Error obtaining public ds key from keystore")
		}
		ds_verify_err := userlib.DSVerify(sender_public_ds_key, encrypted_invitation, ds_signature)
		if ds_verify_err != nil {
			return nil, fmt.Errorf("Warning: Invitation has been tampered with! %v", ds_verify_err)
		}

		// Decrypt invitation
		marshaled_invitation, pke_err := userlib.PKEDec(userdata.PKE_Private, encrypted_invitation)
		if pke_err != nil {
			return nil, fmt.Errorf("Error: Failed to decrypt invitation %v", pke_err)
		}

		// Unmarshal invitation
		var invitation Invitation //User struct to be returned
		if unmarshal_err := json.Unmarshal(marshaled_invitation, &invitation); unmarshal_err != nil {
			return nil, fmt.Errorf("Error unmarshaling invitation struct: %v", unmarshal_err)
		}

		// Use SE_Key_Invitation and HMAC_Key_Invitation to verify and decrypt FileKeys struct
		encrypted_file_keys_tagged, ok_file_keys := userlib.DatastoreGet(invitation.FileKeysUUID)
		if !ok_file_keys {
			return nil, fmt.Errorf("Error obtaining file keys from datastore")
		}
		encrypted_file_keys := encrypted_file_keys_tagged[0 : len(encrypted_file_keys_tagged)-64]
		attatched_hmac_tag_file_keys := encrypted_file_keys_tagged[len(encrypted_file_keys_tagged)-64:]

		computed_hmac_tag_file_keys, computed_hmac_error := userlib.HMACEval(hmac_key_file, encrypted_file_keys)
		_ = computed_hmac_error

		if !(userlib.HMACEqual(attatched_hmac_tag_file_keys, computed_hmac_tag_file_keys)) {
			return nil, fmt.Errorf("Warning: File keys have been tampered with!")
		}

		file_keys_decrypted := userlib.SymDec(invitation.SE_Key_File_Keys, encrypted_file_keys)
		var file_keys_struct FileKeys // FileKeys to be unmarshaled
		if unmarshal_file_keys_err := json.Unmarshal(file_keys_decrypted, &file_keys_struct); unmarshal_file_keys_err != nil {
			return nil, fmt.Errorf("Error unmarshaling file keys: %v", unmarshal_file_keys_err)
		}

		se_key_file = file_keys_struct.SE_Key_File
		hmac_key_file = file_keys_struct.HMAC_Key_File
	}

	// Seperate file and hmac from combined tagged file
	encrypted_file := encrypted_file_tagged[0 : len(encrypted_file_tagged)-64]
	attatched_hmac_tag_file := encrypted_file_tagged[len(encrypted_file_tagged)-64:]

	// Verify HMAC of the file
	computed_hmac_tag_file, computed_hmac_error := userlib.HMACEval(hmac_key_file, encrypted_file)
	_ = computed_hmac_error

	if !(userlib.HMACEqual(attatched_hmac_tag_file, computed_hmac_tag_file)) {
		return nil, fmt.Errorf("Warning: File header has been tampered with!")
	}

	// Decrypt and unmarshal file header
	file_decrypted := userlib.SymDec(se_key_file, encrypted_file)
	var file FileHeader // File header to be unmarshaled
	if unmarshal_header_err := json.Unmarshal(file_decrypted, &file); unmarshal_header_err != nil {
		return nil, fmt.Errorf("Error unmarshaling file header: %v", unmarshal_header_err)
	}

	// Verify and decryt each page in the header
	var accumulated_content []byte
	for i := 0; i < len(file.Page_list); i++ {
		encrypted_page_tagged, ok := userlib.DatastoreGet(file.Page_list[i])
		if !ok {
			return nil, fmt.Errorf("Page does not exist in datastore")
		}

		// Seperate page and hmac from combined tagged file
		encrypted_page := encrypted_page_tagged[0 : len(encrypted_page_tagged)-64]
		attatched_hmac_tag_page := encrypted_page_tagged[len(encrypted_page_tagged)-64:]

		// Verify HMAC of the file
		computed_hmac_tag_page, computed_hmac_error := userlib.HMACEval(file.HMAC_key_page, encrypted_page)
		_ = computed_hmac_error

		if !(userlib.HMACEqual(attatched_hmac_tag_page, computed_hmac_tag_page)) {
			return nil, fmt.Errorf("Warning: File page has been tampered with!")
		}

		// Decrypt and unmarshal page
		page_decrypted := userlib.SymDec(file.SE_key_page, encrypted_page)
		var page Page // File header to be unmarshaled
		if unmarshal_header_err := json.Unmarshal(page_decrypted, &page); unmarshal_header_err != nil {
			return nil, fmt.Errorf("Error unmarshaling file page: %v", unmarshal_header_err)
		}

		// Add page content to accumulated content
		accumulated_content = append(accumulated_content, page.Text...)
	}

	// return all content
	return accumulated_content, nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Before anything, CHECK FOR UPDATES IN DATASTORE (for multiple sessions, in case another session makes an update)
	updated_user_data, get_user_err := GetUser(userdata.Username, userdata.Password)
	if get_user_err != nil { // If somehow the user isn't in datastore, definitely an error lol
		return fmt.Errorf("Error: user info not found: %v", get_user_err.Error())
	}

	// Update attributes of userdata
	userdata.Files_owned = updated_user_data.Files_owned
	userdata.Invitation_list = updated_user_data.Invitation_list
	userdata.Shared_files = updated_user_data.Shared_files

	// Derive file uuid from filename and username
	file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + "0"))[:16])
	if file_uuid_err != nil {
		return file_uuid_err
	}

	// First, check datastore if given user's filename exists
	encrypted_file_tagged, file_exists_in_datastore := userlib.DatastoreGet(file_uuid)
	if !file_exists_in_datastore { // If user is not found in datastore
		return fmt.Errorf("File doesn't exist in datastore:")
	}
	var se_key_file []byte
	var hmac_key_file []byte

	// Then, check if user owns the file
	if file_keys, user_owns_file := userdata.Files_owned[file_uuid]; user_owns_file { // if the user owns the file
		//obtain file keys from Files_owned map
		se_key_file = file_keys[0]
		hmac_key_file = file_keys[1]

	} else { //The file is shared with the user (user does not own the file), and the user will have to access the file via invitation
		// To do: Obtain sender Shared_files, then update invitation (incase of revoked user)
		// Then access file through invitation information
		invitation_uuid, parse_err := uuid.Parse(userdata.Shared_files[filename][1]) //Note: uuid in this case stored as a string
		if parse_err != nil {
			return fmt.Errorf("Error parsing uuid: %v", parse_err)
		}
		sender := userdata.Shared_files[filename][0]

		// When calling acceptInvitation to update the invitation, in this case, if the filename already exists in the user's files_shared namespace, don't error
		// This makes the same invitation_uuid point to the UPDATED invitation with updated keys
		userdata.AcceptInvitation(sender, invitation_uuid, filename)

		// Obtain invitation: The last 256 bytes of the encrypted marshaled invitation will be the DS
		signed_encrypted_invitation, ok := userlib.DatastoreGet(invitation_uuid)
		if !ok {
			return fmt.Errorf("Error obtaining invitation from datastore")
		}
		encrypted_invitation := signed_encrypted_invitation[0 : len(signed_encrypted_invitation)-256]
		ds_signature := signed_encrypted_invitation[len(signed_encrypted_invitation)-256:]

		// verify invitation
		// DS signature will be at the end of the encrypted marshaled invitation
		sender_public_ds_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(sender + "1"))))
		if !ok {
			return fmt.Errorf("Error obtaining public ds key from keystore")
		}
		ds_verify_err := userlib.DSVerify(sender_public_ds_key, encrypted_invitation, ds_signature)
		if ds_verify_err != nil {
			return fmt.Errorf("Warning: Invitation has been tampered with! %v", ds_verify_err)
		}

		// Decrypt invitation
		marshaled_invitation, pke_err := userlib.PKEDec(userdata.PKE_Private, encrypted_invitation)
		if pke_err != nil {
			return fmt.Errorf("Error: Failed to decrypt invitation %v", pke_err)
		}

		// Unmarshal invitation
		var invitation Invitation //User struct to be returned
		if unmarshal_err := json.Unmarshal(marshaled_invitation, &invitation); unmarshal_err != nil {
			return fmt.Errorf("Error unmarshaling invitation struct: %v", unmarshal_err)
		}

		// Use SE_Key_Invitation and HMAC_Key_Invitation to verify and decrypt FileKeys struct
		encrypted_file_keys_tagged, ok_file_keys := userlib.DatastoreGet(invitation.FileKeysUUID)
		if !ok_file_keys {
			return fmt.Errorf("Error obtaining file keys from datastore")
		}
		encrypted_file_keys := encrypted_file_keys_tagged[0 : len(encrypted_file_keys_tagged)-64]
		attatched_hmac_tag_file_keys := encrypted_file_keys_tagged[len(encrypted_file_keys_tagged)-64:]

		computed_hmac_tag_file_keys, computed_hmac_error := userlib.HMACEval(hmac_key_file, encrypted_file_keys)
		_ = computed_hmac_error

		if !(userlib.HMACEqual(attatched_hmac_tag_file_keys, computed_hmac_tag_file_keys)) {
			return fmt.Errorf("Warning: File keys have been tampered with!")
		}

		file_keys_decrypted := userlib.SymDec(invitation.SE_Key_File_Keys, encrypted_file_keys)
		var file_keys_struct FileKeys // FileKeys to be unmarshaled
		if unmarshal_file_keys_err := json.Unmarshal(file_keys_decrypted, &file_keys_struct); unmarshal_file_keys_err != nil {
			return fmt.Errorf("Error unmarshaling file keys: %v", unmarshal_file_keys_err)
		}

		se_key_file = file_keys_struct.SE_Key_File
		hmac_key_file = file_keys_struct.HMAC_Key_File
	}

	// Seperate file and hmac from combined tagged file
	encrypted_file := encrypted_file_tagged[0 : len(encrypted_file_tagged)-64]
	attatched_hmac_tag_file := encrypted_file_tagged[len(encrypted_file_tagged)-64:]

	// Verify HMAC of the file
	computed_hmac_tag_file, computed_hmac_error := userlib.HMACEval(hmac_key_file, encrypted_file)
	_ = computed_hmac_error

	if !(userlib.HMACEqual(attatched_hmac_tag_file, computed_hmac_tag_file)) {
		return fmt.Errorf("Warning: File header has been tampered with!")
	}

	// Decrypt and unmarshal file header
	file_decrypted := userlib.SymDec(se_key_file, encrypted_file)
	var file_header FileHeader // File header to be unmarshaled
	if unmarshal_header_err := json.Unmarshal(file_decrypted, &file_header); unmarshal_header_err != nil {
		return fmt.Errorf("Error unmarshaling file header: %v", unmarshal_header_err)
	}

	// Load most recent page
	encrypted_page_tagged, ok := userlib.DatastoreGet(file_header.Page_list[len(file_header.Page_list)-1])
	if !ok {
		return fmt.Errorf("Page does not exist in datastore")
	}

	// Seperate page and hmac from combined tagged file
	encrypted_page := encrypted_page_tagged[0 : len(encrypted_page_tagged)-64]
	attatched_hmac_tag_page := encrypted_page_tagged[len(encrypted_page_tagged)-64:]

	// Verify HMAC of the file
	computed_hmac_tag_page, computed_hmac_error := userlib.HMACEval(file_header.HMAC_key_page, encrypted_page)
	_ = computed_hmac_error

	if !(userlib.HMACEqual(attatched_hmac_tag_page, computed_hmac_tag_page)) {
		return fmt.Errorf("Warning: File page has been tampered with!")
	}

	// Decrypt and unmarshal latest page
	page_decrypted := userlib.SymDec(file_header.SE_key_page, encrypted_page)
	var latest_page Page // File header to be unmarshaled
	if unmarshal_header_err := json.Unmarshal(page_decrypted, &latest_page); unmarshal_header_err != nil {
		return fmt.Errorf("Error unmarshaling file page: %v", unmarshal_header_err)
	}

	// Append until latest page fills up
	i := 0
	for len(latest_page.Text) <= 256 {
		latest_page.Text = append(latest_page.Text, content[i])
		i++
	}
	// Marshal latest page
	marshaled_latest_page, err_marshal := json.Marshal(latest_page)
	if err_marshal != nil {
		return fmt.Errorf("Error serializing file page: %v", err_marshal)
	}

	// Use the same page uuid
	page_uuid := file_header.Page_list[len(file_header.Page_list)-1]

	// Encrypt and create new HMAC tag for latest page
	encrypted_page = userlib.SymEnc(file_header.SE_key_page, userlib.RandomBytes(16), marshaled_latest_page)
	hmac_tag_page, hmac_error := userlib.HMACEval(file_header.HMAC_key_page, encrypted_page)
	_ = hmac_error

	// Append HMAC tag behind the encrypted page
	encrypted_page_tagged = append(encrypted_page, hmac_tag_page...)

	// Store encrypted page in datastore
	userlib.DatastoreSet(page_uuid, encrypted_page_tagged)

	//keep adding as many pages as needed
	content = content[i:]
	for i = 0; i < len(content); i++ {
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
			}
			// Marshal each page
			marshaled_page, err_marshal := json.Marshal(new_page)
			if err_marshal != nil {
				return fmt.Errorf("Error serializing file page: %v", err_marshal)
			}

			// Generate uuid for page and HMAC tag
			page_uuid := generate_new_uuid()

			// Encrypt and create HMAC tag for each page
			encrypted_page := userlib.SymEnc(file_header.SE_key_page, userlib.RandomBytes(16), marshaled_page)
			hmac_tag_page, hmac_error := userlib.HMACEval(file_header.HMAC_key_page, encrypted_page)
			_ = hmac_error

			// Append HMAC tag behind the encrypted page
			encrypted_page_tagged := append(encrypted_page, hmac_tag_page...)

			// Store encrypted page in datastore
			userlib.DatastoreSet(page_uuid, encrypted_page_tagged)

			// Add new page uuid to file header
			file_header.Page_list = append(file_header.Page_list, page_uuid)
		}
	}
	return nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//If the filename already exists in userdata's Shared_files, it is a call to update the invitation. Otherwise, error
	return nil
}
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Before anything, CHECK FOR UPDATES IN DATASTORE (for multiple sessions, in case another session makes an update)
	var null_uuid uuid.UUID
	updated_user_data, get_user_err := GetUser(userdata.Username, userdata.Password)
	if get_user_err != nil { // If somehow the user isn't in datastore, definitely an error lol
		return null_uuid, fmt.Errorf("Error: user info not found: %v", get_user_err.Error())
	}

	// Update attributes of userdata
	userdata.Files_owned = updated_user_data.Files_owned
	userdata.Invitation_list = updated_user_data.Invitation_list
	userdata.Shared_files = updated_user_data.Shared_files

	var file_uuid uuid.UUID

	// First, che
	return
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
func (userdata *User) ChangeUsername(new_username string) {
	userdata.Username = new_username
}

func main() {
	username := "esong200"
	password := "cs161"

	alice, init_user_err := InitUser(username, password)
	if init_user_err != nil {
		panic(init_user_err)
	}

	aliceLaptop, laptop_err := GetUser(username, password)
	if laptop_err != nil {
		panic(laptop_err)
	}

	_ = aliceLaptop
	test_file := []byte("Hello World this is a test file!")

	// Test store and load file
	store_file_err := alice.StoreFile("test_file.txt", test_file)
	if store_file_err != nil {
		panic(store_file_err)
	}

	loaded_content, load_file_err := aliceLaptop.LoadFile("test_file.txt")
	if load_file_err != nil {
		panic(load_file_err)
	}
	fmt.Println(string(loaded_content))

	to_append := make([]byte, 0)
	for i := 0; i < 50; i++ {
		to_append = append(to_append, []byte("0123456789")...)
	}

	append_file_err := aliceLaptop.AppendToFile("test_file.txt", to_append)
	if append_file_err != nil {
		panic(append_file_err)
	}

	appended_file, load_file_err := alice.LoadFile("test_file.txt")
	if load_file_err != nil {
		panic(load_file_err)
	}
	fmt.Println(string(appended_file))
}
