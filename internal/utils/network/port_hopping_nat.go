package network

// Server-side port hopping needs no per-packet work: the client rotates the
// destination UDP port across a range (see PortHoppingPacketConn) and a single
// NAT REDIRECT rule folds that whole range back onto the one socket the QUIC
// listener binds. conntrack rewrites the replies to the port the client hit, so
// the server stays a single 4-tuple internally while presenting a moving target
// on the wire. These helpers install and remove that rule the same way TCP
// tuning is applied - best effort, Linux only, non-fatal if iptables is missing
// or we lack CAP_NET_ADMIN.
import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
)

// portHoppingRuleSpec is the iptables rule spec shared by the -A/-C/-D forms:
// everything after the action flag (chain, match, target).
func portHoppingRuleSpec(portStart, portEnd, toPort int) []string {
	return []string{
		"PREROUTING",
		"-p", "udp",
		"--dport", strconv.Itoa(portStart) + ":" + strconv.Itoa(portEnd),
		"-j", "REDIRECT",
		"--to-ports", strconv.Itoa(toPort),
	}
}

// PortHoppingRuleCommand returns the human-readable iptables command that
// EnsurePortHoppingRedirect installs, for logging and manual-setup fallback.
func PortHoppingRuleCommand(portStart, portEnd, toPort int) string {
	return fmt.Sprintf("iptables -t nat -A PREROUTING -p udp --dport %d:%d -j REDIRECT --to-ports %d",
		portStart, portEnd, toPort)
}

// EnsurePortHoppingRedirect installs the NAT REDIRECT rule idempotently: it first
// probes with -C so a server restart doesn't stack duplicate rules, adding the
// rule only when absent. It is a no-op on non-Linux platforms. Any failure
// (iptables absent, insufficient privileges) is returned for the caller to log
// non-fatally - the tunnel still works for a client not hopping ports.
func EnsurePortHoppingRedirect(portStart, portEnd, toPort int) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("port-hopping NAT redirect is Linux-only; skipping on %s", runtime.GOOS)
	}
	spec := portHoppingRuleSpec(portStart, portEnd, toPort)

	// -C exits 0 when the rule already exists; only add it when it doesn't.
	if err := exec.Command("iptables", append([]string{"-t", "nat", "-C"}, spec...)...).Run(); err == nil {
		return nil // already present
	}
	if out, err := exec.Command("iptables", append([]string{"-t", "nat", "-A"}, spec...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("install port-hopping NAT rule: %w: %s", err, out)
	}
	return nil
}

// RemovePortHoppingRedirect deletes the rule installed by
// EnsurePortHoppingRedirect. Best effort; a no-op on non-Linux platforms.
func RemovePortHoppingRedirect(portStart, portEnd, toPort int) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	spec := portHoppingRuleSpec(portStart, portEnd, toPort)
	if out, err := exec.Command("iptables", append([]string{"-t", "nat", "-D"}, spec...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("remove port-hopping NAT rule: %w: %s", err, out)
	}
	return nil
}
