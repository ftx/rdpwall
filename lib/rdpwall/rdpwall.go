package rdpwall

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// encodedPS encodes a PowerShell script as base64 UTF-16 LE for use with
// powershell.exe -EncodedCommand. This approach bypasses execution policy and
// avoids all quoting and stdin-pipe issues.
func encodedPS(script string) string {
	b := make([]byte, 0, len(script)*2)
	for _, r := range script {
		b = append(b, byte(r), byte(r>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

const (
	// banWindow is the time window within which failed attempts are counted.
	// An IP is blocked if it exceeds failureThreshold failures within this window.
	// A blocked IP is unbanned once it has zero failures within this window.
	banWindow = 24 * time.Hour

	// failureThreshold is the number of recent failures above which an IP gets blocked.
	failureThreshold = 3

	// scanInterval controls how often the event log is queried.
	// 30s is more than sufficient — the wevtutil query is fast and brute-force
	// protection does not require sub-second reaction time.
	scanInterval = 30 * time.Second

	// blockInterval controls how often pending IPs are committed to the firewall.
	blockInterval = 5 * time.Second
)

func logTime() string {
	return time.Now().Format("15:04:05")
}

type Quantom struct {
	storage Storage
}

// New creates a new Quantom instance.
func New(storage Storage) *Quantom {
	return &Quantom{storage: storage}
}

// evtXMLEvent is the subset of the Windows Event XML schema we care about.
type evtXMLEvent struct {
	System struct {
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// queryRecentFailures queries the Windows Security event log for failed login
// attempts (event 4625) within the last banWindow using the native wevtapi.dll
// API directly — no PowerShell or external process spawn.
func (q *Quantom) queryRecentFailures() (map[string][]FailedAudit, error) {
	query := fmt.Sprintf(
		"*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= %d]]]",
		int64(banWindow/time.Millisecond),
	)

	xmlEvents, err := evtQueryXML("Security", query)
	if err != nil {
		return nil, fmt.Errorf("evtQueryXML: %w", err)
	}

	failedAudits := map[string][]FailedAudit{}
	for _, xmlStr := range xmlEvents {
		// Strip xmlns so plain struct tags match without a namespace prefix.
		xmlStr = strings.Replace(xmlStr,
			` xmlns="http://schemas.microsoft.com/win/2004/08/events/event"`, "", 1)

		var ev evtXMLEvent
		if err := xml.Unmarshal([]byte(xmlStr), &ev); err != nil {
			continue
		}

		var ip, username string
		for _, d := range ev.EventData.Data {
			switch d.Name {
			case "IpAddress":
				ip = d.Value
			case "TargetUserName":
				username = d.Value
			}
		}

		if net.ParseIP(ip) == nil {
			continue
		}

		t, err := time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
		if err != nil {
			continue
		}

		failedAudits[ip] = append(failedAudits[ip], FailedAudit{
			Username: username,
			Time:     t,
		})
	}

	return failedAudits, nil
}

func (q *Quantom) Start() {
	q.importFirewallRules()
	q.reconcileFirewallRules()
	go q.PendBlockIPs()
	go q.BlockIPs()
}

// importFirewallRules reads existing "BlockedByQuantom" firewall rules and
// adds any IPs not already in storage. This is the reverse of
// reconcileFirewallRules and handles the case where the storage file was
// deleted or reset while the firewall rules remained intact.
func (q *Quantom) importFirewallRules() {
	script := "Get-NetFirewallRule -DisplayName 'BlockedByQuantom (RDP Brute Force)' -ErrorAction SilentlyContinue | " +
		"Get-NetFirewallAddressFilter | " +
		"Select-Object -ExpandProperty RemoteAddress"

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPS(script))
	stdout, _ := cmd.Output() // stderr carries CLIXML progress — ignore it, use stdout only
	out := strings.TrimSpace(string(stdout))
	if out == "" {
		fmt.Printf("[%s] IMPORT: no existing firewall rules found\n", logTime())
		return
	}

	existing, err := q.storage.BlockedIPs()
	if err != nil {
		fmt.Printf("[%s] IMPORT ERROR: could not read storage: %v\n", logTime(), err)
		return
	}
	existingSet := make(map[string]struct{}, len(existing))
	for _, ip := range existing {
		existingSet[ip] = struct{}{}
	}

	imported := 0
	for _, line := range strings.Split(out, "\n") {
		ip := strings.TrimSpace(line)
		if net.ParseIP(ip) == nil {
			continue
		}
		if _, ok := existingSet[ip]; ok {
			continue
		}
		if err := q.storage.BlockIP(ip); err != nil {
			fmt.Printf("[%s] IMPORT ERROR: %s: %v\n", logTime(), ip, err)
			continue
		}
		existingSet[ip] = struct{}{}
		imported++
	}

	total, _ := q.storage.BlockedIPs()
	if imported > 0 {
		fmt.Printf("[%s] IMPORT: %d IP(s) imported from firewall — total banned: %d\n", logTime(), imported, len(total))
	} else {
		fmt.Printf("[%s] IMPORT: storage already in sync with firewall (%d banned)\n", logTime(), len(total))
	}
}

// reconcileFirewallRules re-applies firewall block rules for every IP that the
// storage considers blocked. This handles the case where the firewall rules
// were cleared while the software was stopped (e.g. netsh reset, OS reinstall).
// To avoid duplicate rules accumulating across restarts it deletes any existing
// matching rule before re-adding it.
func (q *Quantom) reconcileFirewallRules() {
	blockedIPs, err := q.storage.BlockedIPs()
	if err != nil {
		fmt.Printf("[%s] RECONCILE ERROR: could not read blocked IPs: %v\n", logTime(), err)
		return
	}

	if len(blockedIPs) == 0 {
		fmt.Printf("[%s] RECONCILE: no blocked IPs in storage — nothing to reapply\n", logTime())
		return
	}

	fmt.Printf("[%s] RECONCILE: reapplying firewall rules for %d blocked IP(s)...\n", logTime(), len(blockedIPs))

	for _, ip := range blockedIPs {
		// Delete first so we never accumulate duplicates across restarts.
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			"name=BlockedByQuantom (RDP Brute Force)",
			"remoteip="+ip).Run() // ignore error — rule may not exist yet

		err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name=BlockedByQuantom (RDP Brute Force)",
			"dir=in",
			"action=block",
			"remoteip="+ip).Run()
		if err != nil {
			fmt.Printf("[%s] RECONCILE ERROR: %s: %v\n", logTime(), ip, err)
		} else {
			fmt.Printf("[%s] RECONCILE REAPPLY: %s\n", logTime(), ip)
		}
	}
}

func (q *Quantom) BlockIPs() {
	for {
		ips, err := q.storage.PendingIPsToBeBlocked()
		if err != nil {
			fmt.Printf("[%s] ERROR reading pending IPs: %v\n", logTime(), err)
			time.Sleep(blockInterval)
			continue
		}

		for _, ip := range ips {
			if err := q.BlockIP(ip); err != nil {
				fmt.Printf("[%s] ERROR blocking IP %s: %v\n", logTime(), ip, err)
			}
		}

		time.Sleep(blockInterval)
	}
}

// recentFailureCount returns the number of failures for an IP.
// Since queryRecentFailures already filters by banWindow via the XPath query,
// all audits in the slice are guaranteed to be recent.
func recentFailureCount(audits []FailedAudit) int {
	return len(audits)
}

func (q *Quantom) PendBlockIPs() {
	for {
		data, err := q.queryRecentFailures()
		if err != nil {
			fmt.Printf("[%s] ERROR querying event log: %v\n", logTime(), err)
			time.Sleep(scanInterval)
			continue
		}

		totalIPs := len(data)
		offenders := 0
		newBanned := 0
		newUnbanned := 0

		// Block IPs that exceeded the threshold within the time window.
		for ip, audits := range data {
			if recentFailureCount(audits) > failureThreshold {
				offenders++
				exists, err := q.storage.PendBlockIP(ip)
				if err != nil {
					fmt.Printf("[%s] ERROR pending block for IP %s: %v\n", logTime(), ip, err)
					continue
				}
				if !exists {
					newBanned++
					fmt.Printf("[%s] PENDING BLOCK: %s (%d recent failures in last %s)\n",
						logTime(), ip, recentFailureCount(audits), banWindow)
				}
			}
		}

		// Remove from pending any IP that no longer has recent failures.
		pendingIPs, err := q.storage.PendingIPsToBeBlocked()
		if err != nil {
			fmt.Printf("[%s] ERROR reading pending IPs: %v\n", logTime(), err)
		} else {
			for _, ip := range pendingIPs {
				if recentFailureCount(data[ip]) == 0 {
					fmt.Printf("[%s] REMOVING PENDING: %s (no recent failures)\n", logTime(), ip)
					if err := q.storage.removePendingIP(ip); err != nil {
						fmt.Printf("[%s] ERROR removing pending IP %s: %v\n", logTime(), ip, err)
					}
				}
			}
		}

		// Unblock IPs that have had no failed attempts within the time window.
		blockedIPs, err := q.storage.BlockedIPs()
		if err != nil {
			fmt.Printf("[%s] ERROR reading blocked IPs: %v\n", logTime(), err)
		} else {
			for _, ip := range blockedIPs {
				if recentFailureCount(data[ip]) == 0 {
					newUnbanned++
					fmt.Printf("[%s] UNBLOCKING: %s (no recent failures in last %s)\n", logTime(), ip, banWindow)
					if err := q.UnblockIP(ip); err != nil {
						fmt.Printf("[%s] ERROR unblocking IP %s: %v\n", logTime(), ip, err)
					}
				}
			}
		}

		pendingCount := 0
		if p, err := q.storage.PendingIPsToBeBlocked(); err == nil {
			pendingCount = len(p)
		}
		blockedCount := 0
		if b, err := q.storage.BlockedIPs(); err == nil {
			blockedCount = len(b)
		}

		fmt.Printf("[%s] ── Scan ── %d IPs seen | %d offenders | pending: %d | banned: %d | +%d new | -%d unbanned\n",
			logTime(), totalIPs, offenders, pendingCount, blockedCount, newBanned, newUnbanned)

		time.Sleep(scanInterval)
	}
}

func (q *Quantom) BlockIP(ip string) error {
	cmd := exec.Command("netsh",
		"advfirewall",
		"firewall",
		"add",
		"rule",
		"name=BlockedByQuantom (RDP Brute Force)",
		"dir=in",
		"action=block",
		"remoteip="+ip)

	err := cmd.Run()
	if err != nil {
		return err
	}

	fmt.Printf("[%s] FIREWALL ADD: blocking %s\n", logTime(), ip)
	return q.storage.BlockIP(ip)
}

func (q *Quantom) UnblockIP(ip string) error {
	cmd := exec.Command("netsh",
		"advfirewall",
		"firewall",
		"delete",
		"rule",
		"name=BlockedByQuantom (RDP Brute Force)",
		"remoteip="+ip)

	err := cmd.Run()
	if err != nil {
		return err
	}

	return q.storage.UnblockIP(ip)
}
