// Command verify-url is the native side of the live cross-process interop test.
// Given a base URL, it fetches that counterparty's signed disclosure from
// <url>/.well-known/agent-disclosure over a real socket, structurally parses and
// verifies it (ed25519 signature + the agentId <-> signing-key binding), prints
// the decision, and exits 0 on valid / 1 on invalid or any transport error.
//
// It fails closed: an unreachable endpoint, a non-2xx status, an unreadable body,
// or a malformed/tampered disclosure all map to "refuse" and exit code 1.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	adp "github.com/general-liquidity/agent-disclosure-protocol/go"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) != 1 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: verify-url <baseUrl>")
		fmt.Fprintln(os.Stderr, "  GET <baseUrl>/.well-known/agent-disclosure, verify the signed disclosure.")
		return 1
	}

	base := strings.TrimRight(args[0], "/")
	url := base + "/.well-known/agent-disclosure"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("decision=refuse reason=%q\n", "disclosure unreachable: "+err.Error())
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("decision=refuse reason=%q\n", fmt.Sprintf("disclosure fetch failed (HTTP %d)", resp.StatusCode))
		return 1
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		fmt.Printf("decision=refuse reason=%q\n", "disclosure body unreadable: "+err.Error())
		return 1
	}

	accepted, reason := adp.VerifyRawReason(string(body))
	if !accepted {
		fmt.Printf("decision=refuse reason=%q\n", reason)
		return 1
	}

	fmt.Printf("decision=transact url=%q\n", url)
	return 0
}
