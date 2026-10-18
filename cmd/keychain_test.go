package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/byteness/keyring"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("File keychain passphrase", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		savedPassphrase, savedProtect, savedKeychain := keychainPassphrase, protectKeychain, fileKeychain
		keychainPassphrase, protectKeychain, fileKeychain = "", false, nil
		DeferCleanup(func() {
			keychainPassphrase, protectKeychain, fileKeychain = savedPassphrase, savedProtect, savedKeychain
		})
	})

	// store stores data under key in dir with passphrase, as the keyring
	// library does.
	store := func(key, data, passphrase string) {
		ring, err := keyring.Open(keyring.Config{
			AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
			ServiceName:      KeychainServiceName,
			FileDir:          dir,
			FilePasswordFunc: func(string) (string, error) { return passphrase, nil },
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(ring.Set(keyring.Item{Key: key, Data: []byte(data)})).To(Succeed())
	}

	account := func() string { return filepath.Join(dir, accountKeychainKey) }

	// ring is the file keyring in dir, as a non-interactive command uses it.
	ring := func(protect bool) *fileKeyring {
		return &fileKeyring{dir: dir, protect: protect}
	}

	Describe("checking a passphrase", func() {
		It("isn't wrong when nothing is stored", func() {
			Expect(wrongPassphrase(account(), "")).To(BeFalse())
		})

		It("is wrong only when it doesn't match", func() {
			store(accountKeychainKey, "{}", "")
			Expect(wrongPassphrase(account(), "")).To(BeFalse())
			Expect(wrongPassphrase(account(), "secret")).To(BeTrue())

			store(accountKeychainKey, "{}", "secret")
			Expect(wrongPassphrase(account(), "secret")).To(BeFalse())
			Expect(wrongPassphrase(account(), "")).To(BeTrue())
		})

		It("isn't wrong when the item is corrupt", func() {
			store(accountKeychainKey, "{}", "")
			raw, err := os.ReadFile(account())
			Expect(err).ToNot(HaveOccurred())
			token := string(raw)
			parts := strings.Split(token, ".")
			Expect(parts).To(HaveLen(5))

			flip := func(s string) string {
				if s[0] == 'A' {
					return "B" + s[1:]
				}

				return "A" + s[1:]
			}

			for _, contents := range []string{
				"",
				"not a token",
				"a.b.c.d.e",
				token + "\n",
				token[:len(token)-5],
				strings.Join([]string{parts[0], parts[1], parts[2], flip(parts[3]), parts[4]}, "."),
				strings.Join([]string{parts[0], parts[1], parts[2], parts[3], flip(parts[4])}, "."),
				parts[0] + "....",
			} {
				Expect(os.WriteFile(account(), []byte(contents), 0o600)).To(Succeed())
				Expect(wrongPassphrase(account(), "")).To(BeFalse(), "contents %q", contents)
			}
		})
	})

	Describe("choosing the passphrase", func() {
		It("uses none, without asking, for an unprotected keychain", func() {
			store(accountKeychainKey, "{}", "")
			Expect(ring(false).passphrase()).To(Equal(""))
		})

		It("ignores --keychain-passphrase outside a protecting login when the keychain isn't protected", func() {
			store(accountKeychainKey, "{}", "")
			keychainPassphrase = "secret"
			Expect(ring(false).passphrase()).To(Equal(""))
		})

		It("uses --keychain-passphrase when auth login protects the keychain", func() {
			keychainPassphrase = "secret"
			Expect(ring(true).passphrase()).To(Equal("secret"))
		})

		It("uses --keychain-passphrase for a protected keychain", func() {
			store(accountKeychainKey, "{}", "secret")
			keychainPassphrase = "secret"
			Expect(ring(false).passphrase()).To(Equal("secret"))
		})

		It("rejects a wrong passphrase for a protected keychain", func() {
			store(accountKeychainKey, "{}", "secret")
			keychainPassphrase = "wrong"
			_, err := ring(false).passphrase()
			Expect(err).To(MatchError(ContainSubstring("wrong keychain passphrase")))
		})

		It("needs a passphrase for a protected keychain when not interactive", func() {
			store(accountKeychainKey, "{}", "secret")
			_, err := ring(false).passphrase()
			Expect(err).To(MatchError(ContainSubstring("--keychain-passphrase")))
		})

		It("needs a passphrase to protect the keychain when not interactive", func() {
			_, err := ring(true).passphrase()
			Expect(err).To(MatchError(ContainSubstring("--keychain-passphrase")))
		})
	})

	Describe("using the keyring", func() {
		It("follows the account as it's protected and unprotected", func() {
			r := ring(false)
			store(accountKeychainKey, `"plain"`, "")
			item, err := r.Get(accountKeychainKey)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(item.Data)).To(Equal(`"plain"`))

			store(accountKeychainKey, `"protected"`, "secret")
			_, err = r.Get(accountKeychainKey)
			Expect(err).To(MatchError(ContainSubstring("--keychain-passphrase")))

			keychainPassphrase = "secret"
			item, err = r.Get(accountKeychainKey)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(item.Data)).To(Equal(`"protected"`))

			store(accountKeychainKey, `"plain again"`, "")
			item, err = r.Get(accountKeychainKey)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(item.Data)).To(Equal(`"plain again"`))
		})

		It("keeps an unprotected keychain unprotected", func() {
			store(accountKeychainKey, "{}", "")
			Expect(ring(false).Set(keyring.Item{Key: kbsyncKeychainKey, Data: []byte("{}")})).To(Succeed())
			Expect(wrongPassphrase(filepath.Join(dir, kbsyncKeychainKey), "")).To(BeFalse())
		})

		It("keeps a protected keychain protected", func() {
			store(accountKeychainKey, "{}", "secret")
			keychainPassphrase = "secret"
			Expect(ring(false).Set(keyring.Item{Key: kbsyncKeychainKey, Data: []byte("{}")})).To(Succeed())
			Expect(wrongPassphrase(filepath.Join(dir, kbsyncKeychainKey), "")).To(BeTrue())
		})
	})

	Describe("logging in", func() {
		It("needs a passphrase before contacting Apple when not interactive", func() {
			fileKeychain = ring(true)
			Expect(prepareKeychainLogin(false)).To(MatchError(ContainSubstring("--keychain-passphrase")))
		})

		It("doesn't ask when the passphrase was passed, or the login doesn't protect the keychain", func() {
			fileKeychain = ring(false)
			Expect(prepareKeychainLogin(false)).To(Succeed())

			fileKeychain = ring(true)
			keychainPassphrase = "secret"
			Expect(prepareKeychainLogin(false)).To(Succeed())
		})

		It("checks the passphrase of a protected keychain before contacting Apple", func() {
			store(accountKeychainKey, "{}", "secret")
			for _, protect := range []bool{false, true} {
				keychainPassphrase = ""
				fileKeychain = ring(protect)
				Expect(prepareKeychainLogin(false)).To(MatchError(ContainSubstring("--keychain-passphrase")), "protect %v", protect)

				keychainPassphrase = "wrong"
				Expect(prepareKeychainLogin(false)).To(MatchError(ContainSubstring("wrong keychain passphrase")), "protect %v", protect)

				keychainPassphrase = "secret"
				Expect(prepareKeychainLogin(false)).To(Succeed(), "protect %v", protect)
			}
		})

		It("doesn't change the passphrase of a protected keychain", func() {
			store(accountKeychainKey, "{}", "secret")
			keychainPassphrase = "other"
			err := ring(true).Set(keyring.Item{Key: accountKeychainKey, Data: []byte("{}")})
			Expect(err).To(MatchError(ContainSubstring("wrong keychain passphrase")))
			Expect(wrongPassphrase(account(), "secret")).To(BeFalse())
		})

		It("removes a kbsync cache stored without the passphrase when the account is protected", func() {
			kbsync := filepath.Join(dir, kbsyncKeychainKey)
			keychainPassphrase = "secret"
			setAccount := func() {
				Expect(ring(true).Set(keyring.Item{Key: accountKeychainKey, Data: []byte("{}")})).To(Succeed())
			}

			store(kbsyncKeychainKey, "{}", "secret")
			setAccount()
			Expect(kbsync).To(BeAnExistingFile())

			store(kbsyncKeychainKey, "{}", "")
			setAccount()
			Expect(kbsync).ToNot(BeAnExistingFile())
			Expect(wrongPassphrase(account(), "")).To(BeTrue())
		})

		It("leaves the kbsync cache alone when the account isn't protected", func() {
			store(kbsyncKeychainKey, "{}", "")
			Expect(ring(false).Set(keyring.Item{Key: accountKeychainKey, Data: []byte("{}")})).To(Succeed())
			Expect(filepath.Join(dir, kbsyncKeychainKey)).To(BeAnExistingFile())
		})
	})
})
