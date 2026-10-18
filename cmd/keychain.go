package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/byteness/keyring"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/util"
	"github.com/spf13/cobra"
)

// protectKeychain is set by "auth login --protect-keychain".
var protectKeychain bool

// fileKeychain is the file keyring, if that's the keychain in use.
var fileKeychain *fileKeyring

// Keys pkg/appstore stores in the keychain.
const (
	accountKeychainKey = "account"
	kbsyncKeychainKey  = "kbsync-v1"
)

var errKeychainPassphraseRequired = errors.New("keychain passphrase is required when not running in interactive mode; use the \"--keychain-passphrase\" flag")

// fileKeyring is the keyring used where there's no system keychain (Linux
// without a Secret Service, for example): encrypted files in dir. It's only
// protected with a passphrase if the user asks for that at login, with
// --keychain-passphrase or --protect-keychain; otherwise the passphrase is
// empty and nobody is asked for one. Once protected, it keeps its passphrase
// until the account is revoked.
//
// The files are opened afresh for each operation, so the passphrase suits
// what's stored at the time. (The keyring library keeps the first non-empty
// passphrase it's given, which a long-running "ipatool mcp" would hold on to
// after the account is stored again with another passphrase, or none.)
type fileKeyring struct {
	dir         string
	interactive bool
	// protect is set for an "auth login" that protects the keyring.
	protect bool

	mu sync.Mutex
	// unlocked is the passphrase the user typed to unlock the keyring.
	unlocked string
}

// open opens the keyring, setting *used (if used isn't nil) to the
// passphrase it's read or written with, if any.
func (k *fileKeyring) open(used *string) keyring.Keyring {
	return util.Must(keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.FileBackend},
		ServiceName:     KeychainServiceName,
		FileDir:         k.dir,
		FilePasswordFunc: func(string) (string, error) {
			passphrase, err := k.passphrase()
			if used != nil {
				*used = passphrase
			}

			return passphrase, err
		},
	}))
}

func (k *fileKeyring) Get(key string) (keyring.Item, error) {
	return k.open(nil).Get(key) //nolint:wrapcheck
}

func (k *fileKeyring) Set(item keyring.Item) error {
	var used string
	if err := k.open(&used).Set(item); err != nil {
		return err //nolint:wrapcheck
	}

	// A kbsync cache stored without the account's passphrase would stay
	// readable without it. It's regenerated, and stored with the passphrase,
	// the next time it's needed.
	if item.Key == accountKeychainKey && used != "" {
		kbsync := filepath.Join(k.dir, kbsyncKeychainKey)
		if wrongPassphrase(kbsync, used) {
			_ = os.Remove(kbsync)
		}
	}

	return nil
}

func (k *fileKeyring) Remove(key string) error {
	return k.open(nil).Remove(key) //nolint:wrapcheck
}

// protected reports whether the stored account has a passphrase.
func (k *fileKeyring) protected() bool {
	return wrongPassphrase(filepath.Join(k.dir, accountKeychainKey), "")
}

// passphrase returns the passphrase to read or write the keyring with,
// asking for it if need be.
func (k *fileKeyring) passphrase() (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	protected := k.protected()
	if !protected && !k.protect {
		return "", nil
	}

	passphrase := keychainPassphrase
	if passphrase == "" {
		passphrase = k.unlocked
	}

	if !protected {
		// This login protects the keyring with a new passphrase, which
		// prepareKeychainLogin has asked for if none was passed.
		if passphrase == "" {
			return "", errKeychainPassphraseRequired
		}

		return passphrase, nil
	}

	if passphrase == "" {
		if !k.interactive {
			return "", errKeychainPassphraseRequired
		}

		var err error

		passphrase, err = readPrompt(fmt.Sprintf("enter passphrase to unlock %q (this is separate from your Apple ID password): ", k.dir), true)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}

		// Storing the account with an empty passphrase would quietly drop
		// the protection.
		if passphrase == "" {
			return "", errors.New("this keychain is protected with a passphrase; enter it, or run \"ipatool auth revoke\" and log in again to stop using one")
		}
	}

	// Storing the account at login doesn't read it, so without this a typo
	// would quietly change the passphrase.
	if wrongPassphrase(filepath.Join(k.dir, accountKeychainKey), passphrase) {
		k.unlocked = ""

		return "", errors.New("wrong keychain passphrase; to change it, or if you've forgotten it, run \"ipatool auth revoke\" and log in again")
	}

	if keychainPassphrase == "" {
		k.unlocked = passphrase
	}

	return passphrase, nil
}

// wrongPassphrase reports whether passphrase fails to decrypt the file
// keyring item in file. Only the key failing to unwrap counts: a missing,
// unreadable or corrupt item doesn't, so logging in again can still replace
// it.
func wrongPassphrase(file, passphrase string) bool {
	ring, err := keyring.Open(keyring.Config{
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          filepath.Dir(file),
		FilePasswordFunc: func(string) (string, error) { return passphrase, nil },
	})
	if err != nil {
		return false
	}

	wrong := false

	func() {
		// jose2go, which the keyring library decrypts with, panics on some
		// malformed tokens.
		defer func() { _ = recover() }()

		_, err := ring.Get(filepath.Base(file))

		// The keyring library returns jose2go's error as is, and jose2go has
		// no sentinel error for this.
		wrong = err != nil && strings.Contains(err.Error(), "aes.KeyUnwrap(): integrity check failed")
	}()

	return wrong
}

// readNewPassphrase asks for a new passphrase for the file keyring in dir,
// twice.
func readNewPassphrase(dir string) (string, error) {
	first, err := readPrompt(fmt.Sprintf("enter a passphrase to protect %q (this is separate from your Apple ID password): ", dir), true)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	if first == "" {
		return "", errors.New("the keychain passphrase can't be empty")
	}

	second, err := readPrompt("enter the passphrase again: ", true)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	if first != second {
		return "", errors.New("the passphrases don't match")
	}

	return first, nil
}

// prepareKeychainLogin runs before "auth login" contacts Apple. It settles
// the passphrase the account will be stored with, so a mistake doesn't throw
// away a finished login: if the file keyring is protected already, it asks
// for (or checks) the current passphrase; if the login protects it, and no
// passphrase was passed, it asks for a new one.
func prepareKeychainLogin(interactive bool) error {
	k := fileKeychain
	if k == nil {
		return nil
	}

	if k.protect && keychainPassphrase == "" && !k.protected() {
		if !interactive {
			return errKeychainPassphraseRequired
		}

		passphrase, err := readNewPassphrase(k.dir)
		if err != nil {
			return err
		}

		keychainPassphrase = passphrase
	}

	_, err := k.passphrase()

	return err
}

// newCommandKeychain returns the keychain for cmd: the system keychain, as
// newKeychain opens it, if there is one, or else a fileKeyring in
// stateDirectory.
func newCommandKeychain(cmd *cobra.Command, stateDirectory string, interactive bool) keychain.Keychain {
	fileKeychain = nil

	_, err := openKeyring(keyring.Config{
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.SecretServiceBackend,
		},
		ServiceName:              KeychainServiceName,
		KeychainTrustApplication: true,
	})
	if err == nil {
		return newKeychain(stateDirectory, interactive)
	}

	login := cmd.Name() == "login" && cmd.HasParent() && cmd.Parent().Name() == "auth"
	fileKeychain = &fileKeyring{
		dir:         stateDirectory,
		interactive: interactive,
		protect:     login && (keychainPassphrase != "" || protectKeychain),
	}

	return keychain.New(keychain.Args{
		Keyring: fileKeychain,
		Label:   KeychainServiceName,
	})
}
