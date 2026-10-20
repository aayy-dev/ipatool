//go:build ios

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// enableJIT marks this process as debugged (CS_DEBUGGED) so the Store emulator
// may run the code it generates, and returns what the jailbreak reported.
//
// Modern jailbreaks (Dopamine and its forks on iOS 16+, including iOS 26)
// gate running generated code behind the kernel's CS_DEBUGGED flag ("allowed
// to run with invalid pages"), not the dynamic-codesigning entitlement.
// systemhook only sets it automatically for apps, so a CLI tool like ipatool
// must ask for it itself. jbctl is a jailbreak platform binary permitted to
// set the flag for a given pid.
//
// Best effort: without jbctl (another jailbreak, or none) ipatool carries on,
// and whether the emulator can run depends on the jailbreak.
func enableJIT() (string, error) {
	jbctl := "/var/jb/usr/bin/jbctl"
	if _, err := os.Stat(jbctl); err != nil {
		path, lookErr := exec.LookPath("jbctl")
		if lookErr != nil {
			return "", fmt.Errorf("find jbctl: %w", lookErr)
		}

		jbctl = path
	}

	out, err := exec.Command(jbctl, "proc_set_debugged", strconv.Itoa(os.Getpid())).CombinedOutput()
	result := strings.TrimSpace(string(out))

	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", jbctl, err, result)
	}

	// jbctl exits 0 even when the jailbreak refuses, so check what it said.
	if !strings.Contains(result, "Successfully") {
		return "", fmt.Errorf("%s: %s", jbctl, result)
	}

	return fmt.Sprintf("%s: %s", jbctl, result), nil
}
