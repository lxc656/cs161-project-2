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

	//key: file uuid, value: list of (recipient, invitation uuid (as string), FileKeysUUID, SE_Key_File_Keys) tuples
	Invitation_list map[uuid.UUID][]InvitationListElements

	//key: filename under user's namespace, value: [sender, invitation uuid (as string)]
	Shared_files map[string][2]string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type InvitationListElements struct {
	Recipient        string
	InvitationUUID   uuid.UUID
	FileKeysUUID     uuid.UUID
	SE_Key_File_Keys []byte
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
	FileUUID         uuid.UUID
	Owner            string
	Sender           string // Username of sender
	Recipient        string
	SE_Key_File_Keys []byte
	//HMAC_Key_File_Keys []byte
	FileKeysUUID uuid.UUID
}

// File keys the invitation points to. Changed when a user is revoked from sharing permissions.
type FileKeys struct {
	SE_Key_File   []byte
	HMAC_Key_File []byte
}

// function for removing an element from a list of strings while preserving order
func remove_from_list(l []InvitationListElements, item InvitationListElements) (removed_list []InvitationListElements) {
	// Get index of element to remove
	for i := 0; i < len(l); i++ {
		elements := l[i]
		if elements.Recipient == item.Recipient && elements.InvitationUUID == item.InvitationUUID && elements.FileKeysUUID == item.FileKeysUUID && string(elements.SE_Key_File_Keys) == string(item.SE_Key_File_Keys) {
			return append(l[:i], l[i+1:]...)
		}
	}
	return l
}

//function for generating a new random uuid that has not been taken yet (uuid collision prevention)
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
		keystore_set_err_pke := userlib.KeystoreSet(string(userlib.Hash([]byte(username+"0"))), pke_public)
		if keystore_set_err_pke != nil {
			return nil, fmt.Errorf("While initializing user, error storing %v public pke in keystore", username)
		}
		// Generate and store ds keys
		ds_sign_key, ds_verify_key, err_ds_keygen := userlib.DSKeyGen()
		if err_ds_keygen != nil {
			return nil, fmt.Errorf("Error generating DS key: %v", err_ds_keygen)
		}

		keystore_set_err_ds := userlib.KeystoreSet(string(userlib.Hash([]byte(username+"1"))), ds_verify_key)
		if keystore_set_err_ds != nil {
			return nil, fmt.Errorf("While initializing user, error storing %v public ds in keystore", username)
		}

		new_user := User{
			Username:        username,
			Password:        password,
			PKE_Private:     pke_private,
			DS_Private:      ds_sign_key,
			Files_owned:     make(map[uuid.UUID][2][]byte),
			Invitation_list: make(map[uuid.UUID][]InvitationListElements),
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
		return nil, fmt.Errorf("While GetUser, User doesn't exist in datastore:")
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
		return fmt.Errorf("While updating user, user doesn't exist in datastore")
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

	// Update attributes
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
	file_header_uuid, file_header_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
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

// Idea: maybe create helper function to JUST get file keys, then use this helper function in loadfile and createinvitation
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

	// Derive file uuid (will only work if user owns file)
	attempted_file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if file_uuid_err != nil {
		return nil, file_uuid_err
	}
	// First, check datastore if given user's filename exists

	var file_uuid uuid.UUID
	var se_key_file []byte
	var hmac_key_file []byte

	// Then, check if user owns the file or not, either way obtain keys
	if file_keys, user_owns_file := userdata.Files_owned[attempted_file_uuid]; user_owns_file { // if the user owns the file
		//Might not need this segment (since if it exists in user hashmap, it SHOULD be un datastore)
		// encrypted_file_tagged_test, file_exists_in_datastore := userlib.DatastoreGet(attempted_file_uuid)
		// if !file_exists_in_datastore { // If user is not found in datastore
		// 	return nil, fmt.Errorf("File doesn't exist in datastore:")
		// }
		//_ = encrypted_file_tagged_test
		//obtain file keys from Files_owned map
		se_key_file = file_keys[0]
		hmac_key_file = file_keys[1]
		file_uuid = attempted_file_uuid

	} else { //The file is shared with the user (user does not own the file), and the user will have to access the file via invitation
		// To do: Obtain sender Shared_files, then update invitation (incase of revoked user)
		// Then access file through invitation information
		combined_inv_uuid, parse_err := uuid.Parse(userdata.Shared_files[filename][1]) //Note: uuid in this case stored as a string
		if parse_err != nil {
			return nil, fmt.Errorf("Error parsing uuid: %v", parse_err)
		}
		sender := userdata.Shared_files[filename][0]

		// When calling acceptInvitation to update the invitation, in this case, if the filename already exists in the user's files_shared namespace, don't error
		// This makes the same invitation_uuid point to the UPDATED invitation with updated keys
		//userdata.AcceptInvitation(sender, combined_inv_uuid, filename)

		invitation, unpack_invitation_err := userdata.UnpackInvitation(combined_inv_uuid, sender)
		if unpack_invitation_err != nil {
			return nil, unpack_invitation_err
		}

		// Access and verify FileKeys struct
		encrypted_file_keys_tagged, file_keys_struct_exists := userlib.DatastoreGet(invitation.FileKeysUUID)
		if !file_keys_struct_exists {
			return nil, fmt.Errorf("Error obtaining FileKeys from datastore")
		}
		encrypted_file_keys := encrypted_file_keys_tagged[0 : len(encrypted_file_keys_tagged)-256]
		ds_signature_file_keys := encrypted_file_keys_tagged[len(encrypted_file_keys_tagged)-256:]
		owner_public_ds_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(invitation.Owner + "1"))))
		if !ok {
			return nil, fmt.Errorf("While unpacking invitation, Error obtaining public ds key from keystore")
		}
		ds_verify_err := userlib.DSVerify(owner_public_ds_key, encrypted_file_keys, ds_signature_file_keys)
		if ds_verify_err != nil {
			return nil, fmt.Errorf("Warning: FileKeys has been tampered with! %v", ds_verify_err)
		}

		file_keys_decrypted := userlib.SymDec(invitation.SE_Key_File_Keys, encrypted_file_keys)
		var file_keys_struct FileKeys // FileKeys to be unmarshaled
		if unmarshal_file_keys_err := json.Unmarshal(file_keys_decrypted, &file_keys_struct); unmarshal_file_keys_err != nil {
			return nil, fmt.Errorf("Error unmarshaling file keys: %v", unmarshal_file_keys_err)
		}

		se_key_file = file_keys_struct.SE_Key_File
		hmac_key_file = file_keys_struct.HMAC_Key_File
		file_uuid = invitation.FileUUID
	}

	// After obtaining se and hmac keys, pull tagged file header from datastore
	encrypted_file_tagged, file_exists_in_datastore := userlib.DatastoreGet(file_uuid)
	if !file_exists_in_datastore { // If user is not found in datastore
		return nil, fmt.Errorf("LoadFile Error: File doesn't exist in datastore:")
	}
	// Seperate file and hmac from combined tagged file
	encrypted_file := encrypted_file_tagged[0 : len(encrypted_file_tagged)-64]
	attatched_hmac_tag_file := encrypted_file_tagged[len(encrypted_file_tagged)-64:]

	// Verify HMAC of the file
	computed_hmac_tag_file, computed_hmac_error := userlib.HMACEval(hmac_key_file, encrypted_file)
	_ = computed_hmac_error

	//fmt.Println("DEBUG: attatched_hmac_tag_file: ", attatched_hmac_tag_file)
	//fmt.Println("DEBUG: computed_hmac_tag_file: ", computed_hmac_tag_file)
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

	// Derive file uuid (will only work if user owns file)
	attempted_file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if file_uuid_err != nil {
		return file_uuid_err
	}

	var file_uuid uuid.UUID
	var se_key_file []byte
	var hmac_key_file []byte

	// Then, check if user owns the file or not, either way obtain keys
	if file_keys, user_owns_file := userdata.Files_owned[attempted_file_uuid]; user_owns_file { // if the user owns the file
		//Might not need this segment (since if it exists in user hashmap, it SHOULD be un datastore)
		// encrypted_file_tagged_test, file_exists_in_datastore := userlib.DatastoreGet(attempted_file_uuid)
		// if !file_exists_in_datastore { // If user is not found in datastore
		// 	return nil, fmt.Errorf("File doesn't exist in datastore:")
		// }
		//_ = encrypted_file_tagged_test
		//obtain file keys from Files_owned map
		se_key_file = file_keys[0]
		hmac_key_file = file_keys[1]
		file_uuid = attempted_file_uuid

	} else { //The file is shared with the user (user does not own the file), and the user will have to access the file via invitation
		// To do: Obtain sender Shared_files, then update invitation (incase of revoked user)
		// Then access file through invitation information
		combined_inv_uuid, parse_err := uuid.Parse(userdata.Shared_files[filename][1]) //Note: uuid in this case stored as a string
		if parse_err != nil {
			return fmt.Errorf("Error parsing uuid: %v", parse_err)
		}
		sender := userdata.Shared_files[filename][0]

		// When calling acceptInvitation to update the invitation, in this case, if the filename already exists in the user's files_shared namespace, don't error
		// This makes the same invitation_uuid point to the UPDATED invitation with updated keys
		// userdata.AcceptInvitation(sender, combined_inv_uuid, filename)

		invitation, unpack_invitation_err := userdata.UnpackInvitation(combined_inv_uuid, sender)
		if unpack_invitation_err != nil {
			return unpack_invitation_err
		}

		// Access and verify FileKeys struct
		encrypted_file_keys_tagged, file_keys_struct_exists := userlib.DatastoreGet(invitation.FileKeysUUID)
		if !file_keys_struct_exists {
			return fmt.Errorf("Error obtaining FileKeys from datastore")
		}
		encrypted_file_keys := encrypted_file_keys_tagged[0 : len(encrypted_file_keys_tagged)-256]
		ds_signature_file_keys := encrypted_file_keys_tagged[len(encrypted_file_keys_tagged)-256:]
		owner_public_ds_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(invitation.Owner + "1"))))
		if !ok {
			return fmt.Errorf("While unpacking invitation, Error obtaining public ds key from keystore")
		}
		ds_verify_err := userlib.DSVerify(owner_public_ds_key, encrypted_file_keys, ds_signature_file_keys)
		if ds_verify_err != nil {
			return fmt.Errorf("Warning: FileKeys has been tampered with! %v", ds_verify_err)
		}

		file_keys_decrypted := userlib.SymDec(invitation.SE_Key_File_Keys, encrypted_file_keys)
		var file_keys_struct FileKeys // FileKeys to be unmarshaled
		if unmarshal_file_keys_err := json.Unmarshal(file_keys_decrypted, &file_keys_struct); unmarshal_file_keys_err != nil {
			return fmt.Errorf("Error unmarshaling file keys: %v", unmarshal_file_keys_err)
		}

		se_key_file = file_keys_struct.SE_Key_File
		hmac_key_file = file_keys_struct.HMAC_Key_File
		file_uuid = invitation.FileUUID
	}

	// After obtaining se and hmac keys, pull tagged file header from datastore
	encrypted_file_tagged, file_exists_in_datastore := userlib.DatastoreGet(file_uuid)
	if !file_exists_in_datastore { // If user is not found in datastore
		return fmt.Errorf("LoadFile Error: File doesn't exist in datastore:")
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
	for len(latest_page.Text) <= 256 && i < len(content) {
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

// Helper function for unpacking invitations
// Takes in a pointer to a marshaled list of invitation uuids, returns a single, decrypted combined invitation
func (userdata *User) UnpackInvitation(combined_inv_uuid uuid.UUID, sender_username string) (invitation Invitation, err error) {
	//key: filename, value: [sender, invitation uuid (as string)]
	var null_invitation Invitation

	// When calling acceptInvitation to update the invitation, in this case, if the filename already exists in the user's files_shared namespace, don't error
	// This makes the same invitation_uuid point to the UPDATED invitation with updated keys

	combined_inv_signed, combined_inv_signed_exists := userlib.DatastoreGet(combined_inv_uuid)
	if !combined_inv_signed_exists {
		return null_invitation, fmt.Errorf("Error: combined invitation cannot be found in datastore")
	}

	// Verify combined invitation
	combined_inv_marshaled := combined_inv_signed[0 : len(combined_inv_signed)-256]
	ds_signature_combined_inv := combined_inv_signed[len(combined_inv_signed)-256:]
	sender_public_ds_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(sender_username + "1"))))

	if !ok {
		return null_invitation, fmt.Errorf("While unpacking invitation, Error obtaining public ds key from keystore")
	}
	ds_verify_err := userlib.DSVerify(sender_public_ds_key, combined_inv_marshaled, ds_signature_combined_inv)
	if ds_verify_err != nil {
		return null_invitation, fmt.Errorf("Warning: Invitation has been tampered with! %v", ds_verify_err)
	}

	// Unmarshal then merge invitation into individually encrypted invitation segments
	var inv_uuid_list []uuid.UUID
	inv_uuid_list_unmarshal_err := json.Unmarshal(combined_inv_marshaled, &inv_uuid_list)
	if inv_uuid_list_unmarshal_err != nil {
		return null_invitation, fmt.Errorf("While creating invitation, error unmarshaling combined invitation: %v", inv_uuid_list_unmarshal_err)
	}

	var invitation_marshaled []byte

	// For every invitation segment, verify and decrypt, then combine
	for i := 0; i < len(inv_uuid_list); i++ {
		inv_segment_uuid := inv_uuid_list[i]

		// Pull each invitation segment from datastore
		encrypted_invitation_segment_signed, encrypted_invitation_segment_exists := userlib.DatastoreGet(inv_segment_uuid)
		if !encrypted_invitation_segment_exists {
			return null_invitation, fmt.Errorf("Error: cannot find particular invitation segment in datastore")
		}

		// Verify each segment
		encrypted_invitation_segment := encrypted_invitation_segment_signed[0 : len(encrypted_invitation_segment_signed)-256]
		ds_signature_inv_segment := encrypted_invitation_segment_signed[len(encrypted_invitation_segment_signed)-256:]
		sender_public_ds_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(sender_username + "1"))))
		if !ok {
			return null_invitation, fmt.Errorf("While unpacking invitation, Error obtaining public ds key from keystore")
		}
		ds_verify_err := userlib.DSVerify(sender_public_ds_key, encrypted_invitation_segment, ds_signature_inv_segment)
		if ds_verify_err != nil {
			return null_invitation, fmt.Errorf("Warning: Invitation segment has been tampered with! %v", ds_verify_err)
		}

		// Decrypt each segment
		marshaled_invitation_segment, pke_err := userlib.PKEDec(userdata.PKE_Private, encrypted_invitation_segment)
		if pke_err != nil {
			return null_invitation, fmt.Errorf("Error: Failed to decrypt invitation segment: %v", pke_err)
		}

		// Append each marshaled segment into overall invitation_marshaled list
		invitation_marshaled = append(invitation_marshaled, marshaled_invitation_segment...)
	}

	// Unmarshal invitation to obtain overall invitation structure
	var unpacked_invitation Invitation
	invitation_unmarshal_err := json.Unmarshal(invitation_marshaled, &unpacked_invitation)
	if invitation_unmarshal_err != nil {
		return null_invitation, fmt.Errorf("While unpacking invitation, error unmarshaling invitation: %v", inv_uuid_list_unmarshal_err)
	}

	return unpacked_invitation, nil
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

	// Derive file uuid (will only work if user owns file)
	attempted_file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if file_uuid_err != nil {
		return null_uuid, file_uuid_err
	}

	var se_key_file []byte
	var hmac_key_file []byte
	var invitation_to_send Invitation
	var file_keys_uuid uuid.UUID
	var se_key_file_keys []byte
	// Then, check if user owns the file
	if file_keys, user_owns_file := userdata.Files_owned[attempted_file_uuid]; user_owns_file { // if the user owns the file
		//Might not need this segment (since if it exists in user hashmap, it SHOULD be un datastore)
		// First, check datastore if given user's filename exists
		encrypted_file_tagged, file_exists_in_datastore := userlib.DatastoreGet(attempted_file_uuid)
		if !file_exists_in_datastore { // If user is not found in datastore
			return null_uuid, fmt.Errorf("File doesn't exist in datastore:")
		}
		_ = encrypted_file_tagged

		//obtain file keys from Files_owned map
		se_key_file = file_keys[0]
		hmac_key_file = file_keys[1]

		// Generate UUID for FileKeys
		file_keys_uuid = generate_new_uuid()

		// Create FileKeys struct
		file_keys := FileKeys{
			SE_Key_File:   se_key_file,
			HMAC_Key_File: hmac_key_file,
		}

		// Marshal File_Keys
		file_keys_marshaled, file_marshal_err := json.Marshal(file_keys)
		if file_marshal_err != nil {
			return null_uuid, file_marshal_err
		}

		//Encrypt file keys
		se_key_file_keys = userlib.RandomBytes(16)
		encrypted_file_keys := userlib.SymEnc(se_key_file_keys, userlib.RandomBytes(16), file_keys_marshaled)

		// Since the user OWNS the file, user will sign the filekeys with their DS_private, append to the end of File_Keys
		ds_signature_file_keys, signature_err := userlib.DSSign(userdata.DS_Private, encrypted_file_keys)
		if signature_err != nil {
			return null_uuid, fmt.Errorf("Error creating digital signature: %v", signature_err)
		}

		// Append digital signature behind FileKeys
		encrypted_file_keys_signed := append(encrypted_file_keys, ds_signature_file_keys...)

		//Generate HMAC tag for file keys
		// hmac_key_file_keys := userlib.RandomBytes(16)
		// hmac_tag_file_keys, hmac_error := userlib.HMACEval(hmac_key_file_keys, encrypted_file_keys)
		// _ = hmac_error

		// Append hmac_tag_file_keys behind file_keys
		// encrypted_file_keys_tagged := append(encrypted_file_keys, hmac_tag_file_keys...)

		//Store file keys in datastore
		userlib.DatastoreSet(file_keys_uuid, encrypted_file_keys_signed)

		// Create actual invitation struct to be sent
		invitation_to_send = Invitation{
			FileUUID:         attempted_file_uuid,
			Owner:            userdata.Username,
			Sender:           userdata.Username,
			Recipient:        recipientUsername,
			SE_Key_File_Keys: se_key_file_keys,
			//HMAC_Key_File_Keys: hmac_key_file_keys,
			FileKeysUUID: file_keys_uuid,
		}

	} else { // If the user doesn't own the file they want to share
		// TODO: Access invitation for shared file, then create your own derived invitation

		sender := userdata.Shared_files[filename][0]

		//key: filename, value: [sender, invitation uuid (as string)]
		combined_inv_uuid, parse_err := uuid.Parse(userdata.Shared_files[filename][1])
		if parse_err != nil {
			return null_uuid, fmt.Errorf(parse_err.Error())
		}

		// When calling acceptInvitation to update the invitation, in this case, if the filename already exists in the user's files_shared namespace, don't error
		// This makes the same invitation_uuid point to the UPDATED invitation with updated keys
		//userdata.AcceptInvitation(sender, combined_inv_uuid, filename)

		// Take combined_inv_uuid and return entire decrypted invitation struct
		recieved_invitation, unpack_inv_err := userdata.UnpackInvitation(combined_inv_uuid, sender)
		_ = unpack_inv_err

		// Create derived invitation from information in recieved information
		invitation_to_send = Invitation{
			FileUUID:         recieved_invitation.FileUUID,
			Owner:            recieved_invitation.Owner,
			Sender:           userdata.Username,
			Recipient:        recipientUsername,
			SE_Key_File_Keys: recieved_invitation.SE_Key_File_Keys,
			//HMAC_Key_File_Keys: recieved_invitation.HMAC_Key_File_Keys,
			FileKeysUUID: recieved_invitation.FileKeysUUID,
		}
	}

	// Marshal invitation struct
	invitation_marshaled, invitation_marshal_err := json.Marshal(invitation_to_send)
	if invitation_marshal_err != nil {
		return null_uuid, invitation_marshal_err
	}

	// Obtain recipient's public key
	recipient_public_pke_key, recipient_public_key_exists := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername + "0"))))
	if !recipient_public_key_exists {
		return null_uuid, fmt.Errorf("Error: recipient's public key could not be located")
	}

	var invitation_uuid_list []uuid.UUID

	// Split invitation into chunks of 126 or less bytes
	for i := 0; i < len(invitation_marshaled); i++ {
		if i%126 == 0 {
			var new_invitation_segment []byte
			if i+126 <= len(invitation_marshaled) {
				new_invitation_segment = invitation_marshaled[i : i+126]
			} else {
				new_invitation_segment = invitation_marshaled[i:]
			}

			// For each item in invitations_marshaled_list, encrypt and sign

			// Encrypt invitation segments with recipient's public PKE key
			// Encrypt
			invitation_segment_encrypted, pke_encryption_error := userlib.PKEEnc(recipient_public_pke_key, new_invitation_segment)
			if pke_encryption_error != nil {
				return null_uuid, fmt.Errorf("PKE encryption error: %v", pke_encryption_error)
			}

			// Sign
			ds_signature, signature_err := userlib.DSSign(userdata.DS_Private, invitation_segment_encrypted)
			if signature_err != nil {
				return null_uuid, fmt.Errorf("Error creating digital signature: %v", signature_err)
			}

			// Append signature to encrypted invitation segment
			invitation_segment_encrypted_signed := append(invitation_segment_encrypted, ds_signature...)

			// Generate Invitation segment uuid
			invitation_segment_uuid := generate_new_uuid()

			// Store secured information in datastore
			userlib.DatastoreSet(invitation_segment_uuid, invitation_segment_encrypted_signed)

			invitation_uuid_list = append(invitation_uuid_list, invitation_segment_uuid)
		}
	}

	//Store list of invitation uuids in datastore under single uuid
	var inv_uuids_marshaled []byte
	inv_uuids_marshaled, inv_uuids_marshal_err := json.Marshal(invitation_uuid_list)
	if inv_uuids_marshal_err != nil {
		return null_uuid, fmt.Errorf("Error marshaling uuid pair: %v", inv_uuids_marshal_err)
	}
	combined_inv_uuid := generate_new_uuid()

	// Sign combined uuid
	ds_signature_combined_inv_uuid, signature_err := userlib.DSSign(userdata.DS_Private, inv_uuids_marshaled)
	if signature_err != nil {
		return null_uuid, fmt.Errorf("Error creating digital signature: %v", signature_err)
	}

	// Append signature to encrypted invitation
	inv_uuids_marshaled_signed := append(inv_uuids_marshaled, ds_signature_combined_inv_uuid...)

	userlib.DatastoreSet(combined_inv_uuid, inv_uuids_marshaled_signed)

	// If the user own's the file, update user's InvitationList map
	if file_keys, user_owns_file := userdata.Files_owned[attempted_file_uuid]; user_owns_file {
		_ = file_keys
		// Check if particular file has already been shared
		if inv_uuid_list, user_has_shared_file_already := userdata.Invitation_list[attempted_file_uuid]; user_has_shared_file_already {
			//append to file's shared recipients list
			_ = inv_uuid_list
		} else {
			//create new list for file
			userdata.Invitation_list[attempted_file_uuid] = make([]InvitationListElements, 0)
		}

		invitationElements := InvitationListElements{
			Recipient:        recipientUsername,
			InvitationUUID:   combined_inv_uuid,
			FileKeysUUID:     file_keys_uuid,
			SE_Key_File_Keys: se_key_file_keys,
		}
		userdata.Invitation_list[attempted_file_uuid] = append(userdata.Invitation_list[attempted_file_uuid], invitationElements)

		update_user_error := UpdateUserDataInDatastore(userdata.Username, userdata.Password, userdata)
		if update_user_error != nil {
			return null_uuid, fmt.Errorf("Error updating user's files owned map: %v", update_user_error)
		}
	}

	return combined_inv_uuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//If the filename already exists in userdata's Shared_files, it is a call to update the invitation. Otherwise, error
	// Before anything, CHECK FOR UPDATES IN DATASTORE (for multiple sessions, in case another session makes an update)
	updated_user_data, get_user_err := GetUser(userdata.Username, userdata.Password)
	if get_user_err != nil { // If somehow the user isn't in datastore, definitely an error lol
		return fmt.Errorf("Error: user info not found: %v", get_user_err.Error())
	}

	// Update attributes of userdata
	//key: file uuid, value: [SE_Key_File, HMAC_Key_File]
	userdata.Files_owned = updated_user_data.Files_owned
	userdata.Invitation_list = updated_user_data.Invitation_list
	userdata.Shared_files = updated_user_data.Shared_files

	// Check if filename already exists in user's SharedFiles map
	if map_info, user_has_file := userdata.Shared_files[filename]; user_has_file { // if the user already has the file
		_ = map_info
		return fmt.Errorf("While accepting invitation, filename is already taken")
	}
	// If the use doesn't have the file, load invitation for the first time
	userdata.Shared_files[filename] = [2]string{senderUsername, invitationPtr.String()}
	UpdateUserDataInDatastore(userdata.Username, userdata.Password, userdata)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Before anything, CHECK FOR UPDATES IN DATASTORE (for multiple sessions, in case another session makes an update)
	updated_user_data, get_user_err := GetUser(userdata.Username, userdata.Password)
	if get_user_err != nil { // If somehow the user isn't in datastore, definitely an error lol
		return fmt.Errorf("Error: user info not found: %v", get_user_err.Error())
	}

	// Update attributes of userdata
	//key: file uuid, value: [SE_Key_File, HMAC_Key_File]
	userdata.Files_owned = updated_user_data.Files_owned
	userdata.Invitation_list = updated_user_data.Invitation_list
	userdata.Shared_files = updated_user_data.Shared_files

	// Derive file uuid (will only work if user owns file)
	file_uuid, file_uuid_err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if file_uuid_err != nil {
		return file_uuid_err
	}
	//Check if file is owned by the user. If not we can't revoke
	val, ok := userdata.Files_owned[file_uuid]
	if !ok {
		return fmt.Errorf("The given filename does not exist in the caller’s personal file namespace.")
	}
	_ = val

	//Retrieve list of invitations sent out for this file
	invitation_list, ok := userdata.Invitation_list[file_uuid]
	if !ok {
		return fmt.Errorf("Error: File has not been shared with anyone yet")
	}

	var recipient_found = false
	// Check if user has shared with recipient
	for _, info := range invitation_list {
		// element is the element from someSlice for where we are
		recipient := info.Recipient
		// If we find the recipient we wish to revoke
		if recipient == recipientUsername {
			recipient_found = true
			// Delete invitation to recipient in datastore
			invitation_uuid_to_delete := info.InvitationUUID

			// Delete invitation from user's invitation list
			userlib.DatastoreDelete(invitation_uuid_to_delete)
			struct_to_remove := InvitationListElements{
				Recipient:        recipient,
				InvitationUUID:   info.InvitationUUID,
				FileKeysUUID:     info.FileKeysUUID,
				SE_Key_File_Keys: info.SE_Key_File_Keys,
			}
			new_invitation_list := remove_from_list(invitation_list, struct_to_remove)
			invitation_list = new_invitation_list
			userdata.Invitation_list[file_uuid] = new_invitation_list
			break
		}
		//If the loop doesn't find the recipient to revoke, error
	}
	if !recipient_found {
		return fmt.Errorf("File is not shared with the recipient")
	}

	// Change keys of file (decrypt and re-encrypt)

	// Generate new file keys
	new_se_key_file := userlib.RandomBytes(16)
	new_hmac_key_file := userlib.RandomBytes(16)

	// obtain and decrypt file

	// Obtain old file keys
	old_se_key_file := userdata.Files_owned[file_uuid][0]
	old_hmac_key_file := userdata.Files_owned[file_uuid][1]

	// After obtaining se and hmac keys, pull tagged file header from datastore
	encrypted_file_tagged, file_exists_in_datastore := userlib.DatastoreGet(file_uuid)
	if !file_exists_in_datastore { // If user is not found in datastore
		return fmt.Errorf("RevokeAccess Error: File doesn't exist in datastore:")
	}
	// Seperate file and hmac from combined tagged file
	encrypted_file := encrypted_file_tagged[0 : len(encrypted_file_tagged)-64]
	attatched_hmac_tag_file := encrypted_file_tagged[len(encrypted_file_tagged)-64:]

	// Verify HMAC of the file
	computed_hmac_tag_file, computed_hmac_error := userlib.HMACEval(old_hmac_key_file, encrypted_file)
	_ = computed_hmac_error

	if !(userlib.HMACEqual(attatched_hmac_tag_file, computed_hmac_tag_file)) {
		return fmt.Errorf("Revoke Access Warning: File header has been tampered with!")
	}

	// Decrypt and unmarshal file header
	file_decrypted := userlib.SymDec(old_se_key_file, encrypted_file)

	// Re-encrypt and hmac file with new keys
	//Encrypt file
	encrypted_file = userlib.SymEnc(new_se_key_file, userlib.RandomBytes(16), file_decrypted)

	//Generate HMAC tag for file
	new_hmac_tag_file, hmac_error := userlib.HMACEval(new_hmac_key_file, encrypted_file)
	_ = hmac_error

	// Append hmac_tag_file behind file header
	encrypted_file_tagged = append(encrypted_file, new_hmac_tag_file...)

	// Store this file at the same uuid
	userlib.DatastoreSet(file_uuid, encrypted_file_tagged)

	// For every recipient that the user doesn't want to revoke, access FileKeys of their invitation and modify and resign
	// FileKeys struct
	for _, element := range invitation_list {
		// element is the element from someSlice for where we are

		// Access and verify FileKeys struct
		se_key_file_keys := []byte(element.SE_Key_File_Keys)
		file_keys_uuid := element.FileKeysUUID
		encrypted_file_keys_tagged, file_keys_struct_exists := userlib.DatastoreGet(file_keys_uuid)
		if !file_keys_struct_exists {
			return fmt.Errorf("While revoking access, error obtaining FileKeys from datastore")
		}
		encrypted_file_keys := encrypted_file_keys_tagged[0 : len(encrypted_file_keys_tagged)-256]
		ds_signature_file_keys := encrypted_file_keys_tagged[len(encrypted_file_keys_tagged)-256:]
		owner_public_ds_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username + "1"))))
		if !ok {
			return fmt.Errorf("While revoking access, Error obtaining public ds key from keystore")
		}
		ds_verify_err := userlib.DSVerify(owner_public_ds_key, encrypted_file_keys, ds_signature_file_keys)
		if ds_verify_err != nil {
			return fmt.Errorf("Warning: FileKeys has been tampered with! %v", ds_verify_err)
		}

		file_keys_decrypted := userlib.SymDec(se_key_file_keys, encrypted_file_keys)
		var file_keys_struct FileKeys // FileKeys to be unmarshaled
		if unmarshal_file_keys_err := json.Unmarshal(file_keys_decrypted, &file_keys_struct); unmarshal_file_keys_err != nil {
			return fmt.Errorf("Error unmarshaling file keys: %v", unmarshal_file_keys_err)
		}

		// Update keys in FileKeys struct
		file_keys_struct.SE_Key_File = new_se_key_file
		file_keys_struct.HMAC_Key_File = new_hmac_key_file

		// Marshal, Sign and Re-encrypt FileKeys Struct

		// Marshal File_Keys
		file_keys_marshaled, file_marshal_err := json.Marshal(file_keys_struct)
		if file_marshal_err != nil {
			return file_marshal_err
		}

		//Encrypt file_keys
		encrypted_file_keys = userlib.SymEnc(se_key_file_keys, userlib.RandomBytes(16), file_keys_marshaled)

		// Since the user OWNS the file, user will sign the filekeys with their DS_private, append to the end of File_Keys
		ds_signature_file_keys, signature_err := userlib.DSSign(userdata.DS_Private, encrypted_file_keys)
		if signature_err != nil {
			return fmt.Errorf("While revoking access, error creating digital signature: %v", signature_err)
		}

		// Append digital signature behind FileKeys
		encrypted_file_keys_signed := append(encrypted_file_keys, ds_signature_file_keys...)

		userlib.DatastoreSet(file_keys_uuid, encrypted_file_keys_signed)
	}

	// Update User's FileOwned map
	new_file_keys := [2][]byte{new_se_key_file, new_hmac_key_file}
	userdata.Files_owned[file_uuid] = new_file_keys

	// Update userdata in datastore
	update_user_error := UpdateUserDataInDatastore(userdata.Username, userdata.Password, userdata)
	if update_user_error != nil {
		return fmt.Errorf("Error updating user's invitation list map: %v", update_user_error)
	}

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

	bob, bob_err := InitUser("bob", "123")
	if bob_err != nil {
		panic(bob_err)
	}

	charles, init_user_err := InitUser("charles", "456")
	if init_user_err != nil {
		panic(init_user_err)
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

	append_file_err := alice.AppendToFile("test_file.txt", to_append)
	if append_file_err != nil {
		panic(append_file_err)
	}
	appended_content, load_file_err := aliceLaptop.LoadFile("test_file.txt")
	if load_file_err != nil {
		panic(load_file_err)
	}
	fmt.Println("After appending: ", string(appended_content))

	//Test Create invitation
	invitation_uuid, inv_err := alice.CreateInvitation("test_file.txt", "bob")
	if inv_err != nil {
		panic(inv_err)
	}

	a_to_c_invitation_uuid, inv_err := alice.CreateInvitation("test_file.txt", "charles")
	if inv_err != nil {
		panic(inv_err)
	}

	// Test accept invitation

	accept_invitation_err := bob.AcceptInvitation(alice.Username, invitation_uuid, "bob_file")
	if accept_invitation_err != nil {
		panic(accept_invitation_err)
	}

	bob_file, load_file_err := bob.LoadFile("bob_file")
	if load_file_err != nil {
		panic(load_file_err)
	}
	fmt.Println("Bob's file:", string(bob_file))

	charles_accept_invite_err := charles.AcceptInvitation("esong200", a_to_c_invitation_uuid, "charles_file")
	if charles_accept_invite_err != nil {
		fmt.Println("charles accept invite error", charles_accept_invite_err)
	}
	charles_file, load_file_err := charles.LoadFile("charles_file")
	if load_file_err != nil {
		fmt.Println("charles load file error", load_file_err)
	}
	fmt.Println("Charles's file:", string(charles_file))

	fmt.Println(alice.Invitation_list)
	revoke_err := alice.RevokeAccess("test_file.txt", "charles")
	if revoke_err != nil {
		fmt.Println("revoke_err", revoke_err)
	}

	after_revoke_file, load_file_err := aliceLaptop.LoadFile("test_file.txt")
	if load_file_err != nil {
		panic(load_file_err)
	}

	fmt.Println(after_revoke_file)

}
