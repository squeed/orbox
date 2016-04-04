package main

import "github.com/Yawning/bulb"
import "fmt"
import "log"
import "strings"

// Handle communicating with the Tor process
//
// The primary functions herein are for adding
// and removing that Tor knows how to forward.

// Check if tor is up - needed to run this program
func isTorUp(config *Config) bool {
	_, err := torConn(config)
	if err != nil {
		log.Print(err)
		return false
	}
	return true
}

// Tell tor to open up a transparent socket
// on our given network
func torListen(config *Config, state *State) {
	torconn, err := torConn(config)
	if err != nil {
		log.Fatal("Could not connect to tor", err)
	}

	ip := state.RootAddr.IP.String()
	appendTorConfigValue(torconn, "DNSPort", "9053")
	appendTorConfigValue(torconn, "TransPort", ip+":9040")
	appendTorConfigValue(torconn, "DNSListenAddress", ip)
}

// Tell tor to stop listening to our address
func torUnListen(config *Config, state *State) {
	torconn, err := torConn(config)
	if err != nil {
		log.Print("Could not unlisten from tor... continuing ", err)
		return
	}
	ip := state.RootAddr.IP.String()
	removeTorConfigValue(torconn, "TransPort", ip+":9040")
	removeTorConfigValue(torconn, "DNSListenAddress", ip)
}

// Appends a given value to a tor config keyword
// This happens over the tor configuration port
func appendTorConfigValue(conn *bulb.Conn, keyword string, value string) error {
	existing, err := getConfigMultiValue(conn, keyword)
	if err != nil {
		return err
	}

	newValue := fmt.Sprintf("%s=%s", keyword, value)
	// Check if we can skip b/c this directive already exists
	for _, value := range existing {
		if value == newValue {
			return nil
		}
	}

	existing = append(existing, newValue)

	_, err = conn.Request("SETCONF %s", strings.Join(existing, " "))
	return err
}

// *remove* a given value from a tor config keyword
func removeTorConfigValue(conn *bulb.Conn, keyword string, value string) error {
	existing, err := getConfigMultiValue(conn, keyword)
	if err != nil {
		return err
	}

	result := make([]string, 0, len(existing))

	changed := false

	for _, val := range existing {
		toRemove := fmt.Sprintf("%s=%s", keyword, value)
		log.Println(val, toRemove)
		if val != toRemove {
			result = append(result, val)
		} else {
			changed = true
		}
	}

	if len(result) == 0 {
		result = append(result, keyword)
	}

	// If we found what we're looking for, commit it
	if changed {
		_, err = conn.Request("SETCONF %s", strings.Join(result, " "))
		return err
	}
	return nil
}

// Get all entries for a (potentially) multi-valued
// configuration directive from Tor
//
// This skips all entries without a specific value
func getConfigMultiValue(conn *bulb.Conn, keyword string) ([]string, error) {
	resp, err := conn.Request("GETCONF %s", keyword)
	if err != nil {
		return nil, err
	}

	lines := make([]string, len(resp.Data), len(resp.Data)+1)
	copy(lines, resp.Data)
	lines = append(lines, resp.Reply)

	out := make([]string, 0, len(lines))

	for _, line := range lines {
		if strings.Contains(line, "=") {
			out = append(out, line)
		}
	}
	return out, nil
}

func torConn(config *Config) (*bulb.Conn, error) {
	c, err := bulb.Dial("tcp4", fmt.Sprintf("%s:%d", config.TorHost, config.TorPort))
	if err != nil {
		return nil, err
	}
	c.Debug(true)

	if err := c.Authenticate(config.TorPassword); err != nil {
		return nil, err
	}

	return c, nil
}
