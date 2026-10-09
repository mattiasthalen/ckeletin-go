//go:build !windows

// test/integration/vuln_checks_test.go
//
// Integration tests for the framework's vulnerability checks
// (check-vuln-fast.sh and check-deps.sh) against a stub govulncheck.

package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// govulncheckRun is what the stub replays: real govulncheck v1.3.0 output, cut
// down (the findings run to one advisory and one renumbered trace, the
// load-error path made generic), and how that run exited. notInstalled takes
// govulncheck off PATH instead, as on a machine without it.
type govulncheckRun struct {
	output       string
	exit         int
	notInstalled bool
}

var (
	// Vulnerabilities affect the code, and a trace names a symbol containing
	// "Timeout" (this repository on Go 1.26.4).
	govulncheckFindings = govulncheckRun{exit: 3, output: `=== Symbol Results ===

Vulnerability #1: GO-2026-6617
    HTTP/2 server crash due to HPACK encoder race in net/http
  More info: https://pkg.go.dev/vuln/GO-2026-6617
  Standard library
    Found in: net/http@go1.26.4
    Fixed in: net/http@go1.26.9
    Example traces found:
      #1: pkg/checkmate/progress.go:245:21: checkmate.ProgressModel.View calls fmt.Fprintf, which eventually calls http.http2bufferedWriterTimeoutWriter.Write

Your code is affected by 1 vulnerability from the Go standard library.
Use '-show verbose' for more details.
`}

	// The vulnerability database cannot be reached.
	govulncheckOffline = govulncheckRun{exit: 1, output: `govulncheck: fetching vulnerabilities: Get "https://vuln.go.dev/index/modules.json.gz": proxyconnect tcp: dial tcp 127.0.0.1:9: connect: connection refused
`}

	// The packages do not load.
	govulncheckLoadError = govulncheckRun{exit: 1, output: `govulncheck: loading packages:
There are errors with the provided package patterns:

/work/broken/main.go:3:15: undefined: undefinedFn

For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.
`}

	// A usage error (an unknown flag).
	govulncheckUsage = govulncheckRun{exit: 2, output: "flag provided but not defined: -nosuchflag\n"}

	// govulncheck is not on PATH; the shell exits 127.
	govulncheckNotInstalled = govulncheckRun{notInstalled: true}

	govulncheckClean = govulncheckRun{exit: 0, output: `=== Symbol Results ===

No vulnerabilities found.

Your code is affected by 0 vulnerabilities.
Use '-show verbose' for more details.
`}
)

// vulnSandbox runs a vulnerability check with stubs first on a PATH that holds
// nothing else but the system directories, so a real govulncheck cannot leak
// in, and with a TMPDIR of its own, so the fast scan's cache holds only what
// this sandbox wrote.
type vulnSandbox struct {
	t    *testing.T
	root string
	dir  string
}

// govulncheckStub logs the call, then replays the run the test chose.
const govulncheckStub = "#!/bin/sh\necho \"$*\" >> \"$FAKE_GOVULNCHECK_CALLS\"\ncat \"$FAKE_GOVULNCHECK_OUTPUT\"\nexit \"$FAKE_GOVULNCHECK_EXIT\"\n"

func newVulnSandbox(t *testing.T) *vulnSandbox {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	// check-deps.sh verifies the modules and lists outdated ones before it
	// scans; both succeed, so every check-deps.sh case reaches the scan.
	stubs := map[string]string{
		"go":              "#!/bin/sh\n[ \"$1 $2\" = \"mod verify\" ] && echo \"all modules verified\"\nexit 0\n",
		"go-mod-outdated": "#!/bin/sh\nexit 0\n",
	}
	for name, body := range stubs {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755))
	}
	return &vulnSandbox{t: t, root: projectRoot(t), dir: dir}
}

// run executes a framework script with govulncheck replaying run, plus any
// extra VAR=value settings, and returns the combined output and exit status.
func (s *vulnSandbox) run(script string, run govulncheckRun, env ...string) (string, int) {
	s.t.Helper()
	stub := filepath.Join(s.dir, "bin", "govulncheck")
	if run.notInstalled {
		require.NoError(s.t, os.RemoveAll(stub))
	} else {
		require.NoError(s.t, os.WriteFile(stub, []byte(govulncheckStub), 0o755))
	}
	output := filepath.Join(s.dir, "govulncheck.out")
	require.NoError(s.t, os.WriteFile(output, []byte(run.output), 0o644))

	cmd := exec.Command("bash", filepath.Join(s.root, ".ckeletin", "scripts", script))
	cmd.Dir = s.dir
	cmd.Env = append([]string{
		"PATH=" + filepath.Join(s.dir, "bin") + ":/usr/bin:/bin",
		"HOME=" + s.dir,
		"TMPDIR=" + filepath.Join(s.dir, "tmp"),
		"FAKE_GOVULNCHECK_OUTPUT=" + output,
		"FAKE_GOVULNCHECK_EXIT=" + strconv.Itoa(run.exit),
		"FAKE_GOVULNCHECK_CALLS=" + filepath.Join(s.dir, "calls"),
	}, env...)
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(out), exitErr.ExitCode()
	}
	require.NoError(s.t, err, "running %s", script)
	return string(out), 0
}

// scans reports how many times govulncheck ran in this sandbox.
func (s *vulnSandbox) scans() int {
	s.t.Helper()
	calls, err := os.ReadFile(filepath.Join(s.dir, "calls"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	require.NoError(s.t, err)
	return strings.Count(string(calls), "\n")
}

// incompleteScans are govulncheck runs that did not complete. Exits 1, 2 and
// 127 stand for anything but 0 (no vulnerability affects the code) or 3
// (vulnerabilities do). cause is the part of the error a check must show.
var incompleteScans = []struct {
	name  string
	run   govulncheckRun
	cause string
}{
	{"vulnerability database unreachable", govulncheckOffline, "connection refused"},
	{"packages fail to load", govulncheckLoadError, "undefined: undefinedFn"},
	{"usage error", govulncheckUsage, "flag provided but not defined"},
	{"govulncheck not installed", govulncheckNotInstalled, "command not found"},
}

// TestFastVulnScanReadsGovulncheckExitStatus pins the pre-commit scan
// (check-vuln-fast.sh): it takes govulncheck's verdict from the exit status,
// never from the output, whose call traces can name symbols that look like
// network errors. A scan that did not complete fails and is not cached.
func TestFastVulnScanReadsGovulncheckExitStatus(t *testing.T) {
	t.Run("findings whose trace names a Timeout symbol fail as vulnerabilities and are cached", func(t *testing.T) {
		s := newVulnSandbox(t)
		out, code := s.run("check-vuln-fast.sh", govulncheckFindings)
		assert.Equal(t, 1, code, "findings must fail the scan.\nOutput:\n%s", out)
		assert.Contains(t, out, "Security vulnerabilities detected")
		assert.NotContains(t, strings.ToLower(out), "network", "findings must not read as a network failure")
		assert.NotContains(t, out, "skipped")

		out, code = s.run("check-vuln-fast.sh", govulncheckClean)
		assert.Equal(t, 1, code, "the findings verdict must be cached.\nOutput:\n%s", out)
		assert.Equal(t, 1, s.scans(), "a cached verdict must not rescan")
	})

	for _, tc := range incompleteScans {
		t.Run(tc.name+" fails closed and is not cached", func(t *testing.T) {
			s := newVulnSandbox(t)
			out, code := s.run("check-vuln-fast.sh", tc.run)
			assert.Equal(t, 1, code, "an incomplete scan must fail.\nOutput:\n%s", out)
			assert.Contains(t, out, "did not complete")
			assert.Contains(t, out, tc.cause, "govulncheck's error must be shown")
			assert.Contains(t, out, "SKIP_VULN_CHECK=1", "the offline escape hatch must be named")
			assert.NotContains(t, out, "Security vulnerabilities")

			scansBefore := s.scans()
			out, code = s.run("check-vuln-fast.sh", govulncheckClean)
			assert.Equal(t, 0, code, "the next run must scan again.\nOutput:\n%s", out)
			assert.Equal(t, scansBefore+1, s.scans(), "an incomplete scan must not be cached")
		})
	}

	t.Run("a clean scan passes", func(t *testing.T) {
		s := newVulnSandbox(t)
		out, code := s.run("check-vuln-fast.sh", govulncheckClean)
		assert.Equal(t, 0, code, "Output:\n%s", out)
		assert.Contains(t, out, "No vulnerabilities found")
	})

	t.Run("SKIP_VULN_CHECK=1 passes without scanning", func(t *testing.T) {
		s := newVulnSandbox(t)
		out, code := s.run("check-vuln-fast.sh", govulncheckFindings, "SKIP_VULN_CHECK=1")
		assert.Equal(t, 0, code, "Output:\n%s", out)
		assert.Equal(t, 0, s.scans())
	})
}

// TestDepsCheckReadsGovulncheckExitStatus pins check-deps.sh (check:deps): it
// labels govulncheck's verdict by the exit status, so findings are never
// reported as a network error and an incomplete scan never as findings.
func TestDepsCheckReadsGovulncheckExitStatus(t *testing.T) {
	t.Run("findings whose trace names a Timeout symbol fail as vulnerabilities", func(t *testing.T) {
		out, code := newVulnSandbox(t).run("check-deps.sh", govulncheckFindings)
		assert.Equal(t, 1, code, "Output:\n%s", out)
		assert.Contains(t, out, "Security vulnerabilities found")
		assert.NotContains(t, strings.ToLower(out), "network", "findings must not read as a network failure")
	})

	for _, tc := range incompleteScans {
		t.Run(tc.name+" fails as an incomplete scan", func(t *testing.T) {
			out, code := newVulnSandbox(t).run("check-deps.sh", tc.run)
			assert.Equal(t, 1, code, "Output:\n%s", out)
			assert.Contains(t, out, "did not complete")
			assert.Contains(t, out, tc.cause, "govulncheck's error must be shown")
			assert.NotContains(t, out, "Security vulnerabilities")
			assert.NotContains(t, out, "All dependencies verified", "an incomplete scan must not report success")
		})
	}

	t.Run("a clean scan passes", func(t *testing.T) {
		out, code := newVulnSandbox(t).run("check-deps.sh", govulncheckClean)
		assert.Equal(t, 0, code, "Output:\n%s", out)
		assert.Contains(t, out, "All dependencies verified and secure")
	})
}
