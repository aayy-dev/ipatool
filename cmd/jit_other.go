//go:build !ios

package cmd

// enableJIT is only needed on iOS, where the Store emulator runs JIT code
// under a jailbreak's code-signing enforcement. Everywhere else the emulator
// uses a prebuilt Unicorn and needs no special memory permissions.
func enableJIT() (string, error) { return "", nil }
