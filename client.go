package client

// CS 161 Project 2

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
	Username  []byte
	Password  []byte
	Sksign    userlib.DSSignKey
	Skdecrypt userlib.PKEDecKey
	FileNames []string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Content string
	UUID    string
	FilePointer int
}

type FilePointer struct {
	NextAddress int
}

type FileChunk struct {
	FileAddress int
	LastChunk   bool
	Content     byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	user_len := len(username)

	if user_len == 0 {
		fmt.Println("Invalid username. Username length must be greater than 0")
	} else {
		hash := userlib.Hash([]byte(username))
		usernameUUID, err := uuid.FromBytes(hash[len(hash)-16:])
		if err != nil {
			fmt.Println("An error occurred while generating a new UUID: ")
		}

		// Check if username has already been taken
		if _, ok := userlib.DatastoreGet(usernameUUID); ok {
			fmt.Println("This username already exists. Choose another username!")
		} else {
			userdata.Username = hash
			userdata.Password = userlib.Hash([]byte(password))
			userdata.FileNames = []string{}

			var pkencrypt userlib.PKEEncKey
			var skdecrypt userlib.PKEDecKey
			pkencrypt, skdecrypt, _ = userlib.PKEKeyGen()

			userdata.Skdecrypt = skdecrypt

			PKstoreset := append(userdata.Username[len(userdata.Username)-13:], []byte("PKE")...)

			pkencryptUUID, err := uuid.FromBytes(PKstoreset[:16])
			if err != nil {
				fmt.Println("An error occurred while generating a UUID")
			}

			userlib.KeystoreSet(pkencryptUUID.String(), pkencrypt)

			DSsignkey, DSverifykey, _ := userlib.DSKeyGen()

			userdata.Sksign = DSsignkey     

			DSstoreset := append(userdata.Username[len(userdata.Username)-14:], []byte("DS")...)

			DSverifyUUID, err := uuid.FromBytes(DSstoreset[:16])
			if err != nil {
				fmt.Println("An error occurred while generating a UUID")
			}

			userlib.KeystoreSet(DSverifyUUID.String(), DSverifykey)

			DataStoreEncrypt, err := userlib.HashKDF(usernameUUID[:16], []byte("User"))
			if err != nil {
				fmt.Println("An error occurred while generating derived key")
			}

			IV := userlib.RandomBytes(16)

			userdatabytes, err := json.Marshal(userdata)
			if err != nil {
				fmt.Println("An error occurred while converting struct to JSON.")
			}

			UserEncrypted := userlib.SymEnc(DataStoreEncrypt[:16], IV, userdatabytes)

			Signature, err := userlib.DSSign(DSsignkey, UserEncrypted)
			if err != nil {
				fmt.Println("Something went wrong in signing.")
			}
			UserEncDS := append(UserEncrypted, Signature...)

			userlib.DatastoreSet(usernameUUID, UserEncDS)
		}
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	hash := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(hash[len(hash)-16:])
	if err != nil {
		fmt.Println("An error occurred while generating a new UUID: ")
	}

	// Check if username exist
	if _, ok := userlib.DatastoreGet(usernameUUID); !ok {
		fmt.Println("This username does not exist.")
	} else {
		DSstoresetup := append(hash[len(hash)-14:], []byte("DS")...)

		//Process to obtain DS Verification key from keystore
		DSverifyUUID, err := uuid.FromBytes(DSstoresetup[:16])
		if err != nil {
			fmt.Println("An error occurred while generating a UUID")
		}

		DSVerifykey, ok := userlib.KeystoreGet(DSverifyUUID.String())
		if !ok {
			fmt.Println("Error in retrieving DS verification key")
		}

		//Get user data from datastore
		UsernameUUID, err := uuid.FromBytes(hash[len(hash)-16:])
		if err != nil {
			fmt.Println("An error occurred while generating a new UUID: ")
		}
		UserEncDS, ok := userlib.DatastoreGet(UsernameUUID)
		if !ok {
			fmt.Println("No data at given UUID")
		}

		//Verify integrity of User data
		if err := userlib.DSVerify(DSVerifykey, UserEncDS[:(len(UserEncDS)-256)], UserEncDS[(len(UserEncDS)-256):]); err != nil {
			fmt.Println("Verification of DS failed.")
		} else {
			DataStoreEncrypt, err := userlib.HashKDF(usernameUUID[:16], []byte("User"))
			if err != nil {
				fmt.Println("An error occurred while generating derived key")
			}
			//Obtaon User data decrypted
			UserDecrypted := userlib.SymDec(DataStoreEncrypt[:16], UserEncDS[:len(UserEncDS)-256])
			err = json.Unmarshal(UserDecrypted, userdataptr)
			if err != nil {
				return nil, err
			}
		}
	}

	return userdataptr, nil
}
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash(append([]byte(filename), userdata.Username...))[:16])
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


func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash(append([]byte(filename), userdata.Username...))[:16])
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

	func (userdata *User) AppendToFile(filename string, content[] byte) error {
		
		//encrypting public key
		storageKey, err := uuid.FromBytes(userlib.Hash(append([]byte(filename), userdata.Username...))[:16])
		ivgen := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		if err != nil {
			fmt.Println("An error occurred while generating an IV ")
		}

		//encrypting the file
		encryptedFile := userlib.SymEnc(storageKey[:],ivgen,content)	
		if err != nil {
			fmt.Println("An error occurred while encrypting ")
		}

		//sigining the file
		DSsignkey, DSverifykey, _ := userlib.DSKeyGen()
		userdata.Sksign = DSsignkey     
		Signature, err := userlib.DSSign(DSsignkey, encryptedFile)
		if err != nil {
			fmt.Println("Something went wrong in signing.")
		}
		UserEncDS := append(UserEncrypted, Signature...)
		
		//initiate the file
		var file File
		//file UUID to be added
		file.FilePointer := "//uuid of file from getfile"
		userlib.DatastoreSet("//fileUUID", UserEncDS)
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

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b

}

func FileChunker(fileAdd int, lastchunk bool, content[] byte) (err error) {
    var filedata File
    arr := content
    limit := 1

    for i := 0; i < len(arr); i += limit {
        batch := arr[i:min(i+limit, len(arr))]
        //converts batch into byte
        batchele := batch[0]
        fmt.Println(batch)
		//adds the current chink into the Chunk struct
        filedata.Chunks = append(filedata.Chunks, batchele)
    }
    
    if err != nil {
        return err
    }
	return
}

