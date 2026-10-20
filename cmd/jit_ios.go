//go:build ios

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// enableJIT marks this process as debugged (CS_DEBUGGED) so the SAP emulator
// can map executable (JIT) memory, and returns what the jailbreak reported.
//
// Modern jailbreaks (Dopamine and its forks on iOS 16+, including iOS 26)
// gate JIT behind the kernel's CS_DEBUGGED flag — "allowed to run with
// invalid pages" — not the dynamic-codesigning entitlement. systemhook only
// sets it automatically for apps, so a CLI tool like ipatool must ask for it
// itself; otherwise the emulator's mprotect(PROT_EXEC) is rejected and the
// process aborts with "protect Unicorn translation buffer: Permission
// denied". jbctl is a jailbreak platform binary permitted to set the flag for
// a given pid.
//
// Best effort: if jbctl isn't present (another jailbreak, or none) the
// emulator still runs where the kernel already permits JIT, and fails with
// its own error where it doesn't.
func enableJIT() (string, error) {
	pid := strconv.Itoa(os.Getpid())

	var lastErr error

	for _, jbctl := range []string{"/var/jb/usr/bin/jbctl", "jbctl"} {
		out, err := exec.Command(jbctl, "proc_set_debugged", pid).CombinedOutput()
		if err == nil {
			return fmt.Sprintf("%s: %s", jbctl, strings.TrimSpace(string(out))), nil
		}

		lastErr = fmt.Errorf("%s: %w: %s", jbctl, err, strings.TrimSpace(string(out)))
	}

	return "", lastErr
}
