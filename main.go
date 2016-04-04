package main

import "fmt"
import "net"
import "os"

import "os/exec"
import "runtime"
import "log"
import "github.com/vishvananda/netns"
import "github.com/vishvananda/netlink"

import flag "github.com/spf13/pflag"

type State struct {
	RootNs     netns.NsHandle
	TorNs      netns.NsHandle
	RootIfName string
	TorIfName  string

	RootIf netlink.Link
	TorIf  netlink.Link

	RootAddr *netlink.Addr
	TorAddr  *netlink.Addr

	// Whether or not iptables has been setup
	NatEnabled bool

	Uid, Euid int
	Gid, Egid int
}

type Config struct {
	TorHost     string // The address of the tor control port
	TorPort     int    // The tor control port
	TorPassword string // The auth secret for tor
	Command     []string
}

var state State

func parseArgs() *Config {
	config := &Config{}

	flag.IntVarP(&config.TorPort, "control-port", "p",
		9051, "The tor conntrol port")
	flag.StringVarP(&config.TorHost, "control-host", "h",
		"127.0.0.1", "The tor control host")

	flag.StringVarP(&config.TorPassword, "control-pw", "s",
		"", "The tor control secret")

	flag.Parse()

	config.Command = flag.Args()

	return config
}

func main() {
	config := parseArgs()
	state = State{}
	var err error

	if !isTorUp(config) {
		log.Fatal("Tor is not up! cannot continue")
		os.Exit(2)
	}
	// This will fail if we can't access iptables
	getIptablesPath()

	// Needed beause namespaces are per-OS-thread
	// and there is no clear distinction in golang
	runtime.LockOSThread()
	runtime.GOMAXPROCS(1)

	//Get a handle to the current namespace
	state.RootNs, err = netns.Get()
	if err != nil {
		log.Fatal("Could not get current ns ", err)
	}

	// Create the tor netns
	initTorNs(&state)

	// Create the veth pair between the netns
	initVeth(&state)

	// Switch back to the root NS
	setNs(&state, false)

	// Direct tor to listen to the interface created by tor
	torListen(config, &state)

	// Set up nat to Tor
	initNat(&state)
	setNs(&state, true)

	log.Println("That should be everything...")
	log.Print("Hit enter to run\n")

	doExec(config.Command)

	// Do some cleanup
	cleanup(config, &state)

}

// Clean up any operations
func cleanup(config *Config, state *State) {
	setNs(state, false)

	deleteNat(state)
	torUnListen(config, state)

	if state.RootIf != nil {
		netlink.LinkDel(state.RootIf)
	}

	// This doesn't delete the namespace, it just closes
	// our filehandle. The NS goes away when we quit
	if state.TorNs.IsOpen() {
		state.TorNs.Close()
	}

	if state.RootNs.IsOpen() {
		state.RootNs.Close()
	}
}

// Generates the veth name
// This will just be vethTor<PID>
func getVethName() (string, string) {
	pid := os.Getpid()

	return fmt.Sprintf("vethTor%v", pid), fmt.Sprintf("vethTorC%v", pid)

}

// Given the initialized namespaces, create a veth
// pair for inter-communication.
// There are a few distinct steps:
// 1. Create a veth pair
// 2. Assign the "far" side of the pair to the Tor netns
// 3. Assign addresses to them both
func initVeth(state *State) {

	// We generate a veth pair based on the pid
	// so there won't be conflicts
	state.RootIfName, state.TorIfName = getVethName()

	//Create the veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  state.RootIfName,
			Flags: net.FlagUp,
			MTU:   1500,
		},
		PeerName: state.TorIfName,
	}

	err := netlink.LinkAdd(veth)
	if err != nil {
		log.Fatal("Could not create veth pair ", err)
	}
	state.RootIf = veth
	state.TorIf, err = netlink.LinkByName(veth.PeerName)
	if err != nil {
		log.Fatal("Could not retrieve veth ", err)
	}
	// TODO close link

	// Assign some addresses
	state.RootAddr, state.TorAddr = makeAddresses()
	log.Println("Trying to set address: ", state.RootAddr)

	state.RootAddr.Label = state.RootIf.Attrs().Name

	err = netlink.AddrAdd(state.RootIf, state.RootAddr)
	if err != nil {
		log.Fatal("Could not set addr for link ", err)
	}
	err = netlink.LinkSetUp(state.RootIf)
	if err != nil {
		log.Fatal("Could not up link ", err)
	}

	//Assign the far side of the pair to the Tor NS
	err = netlink.LinkSetNsFd(state.TorIf, int(state.TorNs))
	if err != nil {
		log.Fatal("Could not set NS for tor link ", err)
	}

	// Switch to the tor namespace and add
	// the address and routing
	setNs(state, true)

	log.Println("Trying to set address: ", state.TorAddr)

	state.TorAddr.Label = state.TorIf.Attrs().Name
	err = netlink.AddrAdd(state.TorIf, state.TorAddr)
	if err != nil {
		log.Fatal("Could not set addr for link ", err)
	}

	state.TorIf, err = netlink.LinkByName(state.TorIfName)
	if err != nil {
		log.Fatal("Could not refresh interface ", err)
	}
	log.Printf("%+v\n", state.TorIf)
	foo, err := netlink.AddrList(state.TorIf, netlink.FAMILY_V4)

	log.Printf("%+v\n", foo)

	err = netlink.LinkSetUp(state.TorIf)
	if err != nil {
		log.Fatal("Could not up link ", err)
	}

	defaultRoute := &netlink.Route{
		LinkIndex: state.TorIf.Attrs().Index,
		Gw:        state.RootAddr.IP,
	}
	err = netlink.RouteAdd(defaultRoute)
	if err != nil {
		log.Fatal("Could not set gateway ", err)
	}
	fmt.Printf("Root: %+v\n", veth)
	fmt.Printf("Tor: %+v\n", state.TorIf)

	setNs(state, false)

}

// Switch the namespace in which the current
// thread runs
func setNs(state *State, tor bool) {
	debugname := "host"
	destNs := state.RootNs
	if tor {
		debugname = "tor"
		destNs = state.TorNs
	}

	log.Printf("Switching namespace to %s\n", debugname)

	currNs, err := netns.Get()
	if err != nil {
		log.Fatal("Could not get current NS to switch", err)
	}

	if currNs.Equal(destNs) {
		log.Println("Namespace is already correct! Byebye")
		return
	}

	err = netns.Set(destNs)
	if err != nil {
		log.Fatal("Could not switch to namespace", debugname, err)
	}
}

// Create a new anonymous network namespace
func initTorNs(state *State) {
	var err error

	log.Printf("Creating Tor netns...\n")
	state.TorNs, err = netns.New()
	if err != nil {
		log.Fatal("Could not create new NS ", err)
	}
	log.Printf("Created Tor NS with FD %v\n", int(state.TorNs))

	log.Printf("Bringing loopback up")
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		log.Fatal("Could not get lo...? ", err)
	}
	netlink.LinkSetUp(lo)

	setNs(state, false) //Switch to Root NS
}

func debugExtIp() {
	cmd := exec.Command("curl",
		"-v", "https://api.ipify.org?format=json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("Huh? ", err)
	}
}
