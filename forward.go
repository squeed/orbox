package main

import "log"
import "os"
import "os/exec"

// Set up the Iptables rules to transparently forward
// traffic from the NS'd lan to Tor
//
// This is taken from from the Tor documentation:
// 	https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy
//
// TODO: explicitly block all other traffic
func initNat(state *State) {
	path := getIptablesPath()
	cmd := exec.Command(path,
		"-t", "nat",
		"-A", "PREROUTING",
		"-i", state.RootIf.Attrs().Name,
		"-p", "tcp", "--syn",
		"-j", "REDIRECT",
		"--to-ports", "9040")
	cmd.Stderr = os.Stderr

	log.Printf("%v\n", cmd.Args)
	err := cmd.Run()
	if err != nil {
		log.Fatal("Could not create TCP nat rule", err)
	}

	cmd = exec.Command(path,
		"-t", "nat",
		"-A", "PREROUTING",
		"-i", state.RootIf.Attrs().Name,
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT",
		"--to-ports", "9053")
	cmd.Stderr = os.Stderr

	log.Printf("%v\n", cmd.Args)
	err = cmd.Run()
	if err != nil {
		log.Fatal("Could not create DNS nat rule", err)
	}
}

func deleteNat(state *State) {
	path := getIptablesPath()
	cmd := exec.Command(path,
		"-t", "nat",
		"-D", "PREROUTING",
		"-i", state.RootIf.Attrs().Name,
		"-p", "tcp", "--syn",
		"-j", "REDIRECT",
		"--to-ports", "9040")
	cmd.Stderr = os.Stderr

	log.Printf("%v\n", cmd.Args)
	err := cmd.Run()
	if err != nil {
		log.Println("Could not delete tcp nat rule", err)
	}

	cmd = exec.Command(path,
		"-t", "nat",
		"-D", "PREROUTING",
		"-i", state.RootIf.Attrs().Name,
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT",
		"--to-ports", "9053")
	cmd.Stderr = os.Stderr

	log.Printf("%v\n", cmd.Args)
	err = cmd.Run()
	if err != nil {
		log.Println("Could not delete DNS nat rule", err)
	}
}

// Get the path to iptables
// We use this because a lot of normal users
// dont have /sbin on their path
func getIptablesPath() string {

	// try obvious choice
	_, err := os.Stat("/sbin/iptables")
	if err == nil {
		return "/sbin/iptables"
	}
	path, err := exec.LookPath("iptables")
	if err != nil {
		log.Fatal("Could not find iptables")
	}
	return path
}
