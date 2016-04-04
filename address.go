package main

import "net"
import "log"
import "fmt"
import "github.com/vishvananda/netlink"

import "math/rand"

// Handle IP Address management
// We need to set up a lot of subnets,
// so we pick them at random :-)

// Given a network (net addr + netmask), generate
// two addresses in that network
func makeAddresses() (*netlink.Addr, *netlink.Addr) {
	subnet := findFreeSubnet()
	host, err := netlink.ParseAddr(subnet.String())
	if err != nil {
		log.Fatal(err)
	}
	tor, _ := netlink.ParseAddr(subnet.String())

	host.IP[len(host.IP)-1]++
	tor.IP[len(tor.IP)-1] += 2

	return host, tor

}

// Find a random place in 10.x.x.x, carve out a /30, and
// look to see if it is already used
// If not, we've got our target
//
// TODO: Allow this to be configurable
func findFreeSubnet() *net.IPNet {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		log.Fatal("Could not list addresses", err)
	}

	var trycidr string
	var tryNet *net.IPNet
	var firstIP net.IP

	found := false

OuterLoop:
	for triesLeft := 20; triesLeft > 0; triesLeft-- {
		trycidr = fmt.Sprintf("10.%d.%d.0/30", rand.Intn(256), rand.Intn(250))
		log.Printf("Trying net %v\n", trycidr)

		firstIP, tryNet, err = net.ParseCIDR(trycidr)
		if err != nil {
			log.Fatal("I somehow created an invalid network", trycidr, err)
		}

		for _, checkAddr := range addrs {
			if checkAddr.IPNet.Contains(firstIP) {
				log.Printf("IP %v is in network %v!\n", firstIP, checkAddr.IPNet.String())
			} else {
				log.Println(tryNet.String(), "looks good...")
				found = true
				break OuterLoop
			}
		}
	}

	if found == false {
		log.Fatal("Could not find an address")
	}
	return tryNet
}
