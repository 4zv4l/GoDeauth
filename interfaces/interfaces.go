package interfaces

import (
	"deauth/userIO"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

type iface struct {
	Name  string
	Mode  bool
	Inter pcap.Interface
}

// askInterface ask the user to select an interface
func AskInterface() (iface, error) {
	ifacesList := GetInterfaces()
	ShowInterfaces(ifacesList)
	choice := ""
	for choice == "" {
		choice = userIO.Prompt("Select an interface: ")
		if choice == "" {
			// return to previous line
			fmt.Print("\033[F")
		}
	}
	// from string to net.interface
	for _, inter := range ifacesList {
		if choice == inter.Name {
			i := iface{Name: choice, Inter: inter}
			i.Mode = i.GetMode()
			fmt.Println(i)
			return i, nil
		}
	}
	return iface{}, errors.New(choice + " : not a valid interface")
}

// return array of interfaces
func GetInterfaces() []pcap.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("err :", err)
		return nil
	}
	// convert net.interfaces to pcap.interfaces
	var pcapIfaces []pcap.Interface
	for _, inter := range ifaces {
		pcapIfaces = append(pcapIfaces, pcap.Interface{Name: inter.Name})
	}
	return pcapIfaces
}

// show all the interfaces
func ShowInterfaces(ifaces []pcap.Interface) {
	fmt.Println("Available interfaces:")
	for _, inter := range ifaces {
		fmt.Println("\t", inter.Name)
	}
}

// return true if the interface is in Monitor Mode
// false if the interface is not yet in Monitor Mode
func (i iface) GetMode() bool {
	// TODO check if the interface is already in Monitor Mode
	return false
}

func (i *iface) SetMonitorMode() error {
	// TODO set the interface to Monitor Mode
	return nil
}

// scan for access points and return array of mac addresses
func (i iface) GetAPs() []string {
	// TODO scan for access points
	return nil
}

func showAPs(aps []string) {
	fmt.Println("Available access points:")
	for _, ap := range aps {
		fmt.Println("\t", ap)
	}
}

// ask the user to select an access point
func AskAP(aps []string) string {
	showAPs(aps)
	choice := ""
	for choice == "" {
		choice = userIO.Prompt("Select an access point: ")
		if choice == "" {
			// return to previous line
			fmt.Print("\033[F")
		}
	}
	return choice
}

func (i iface) GetClients(mac string) []string {
	// TODO scan for clients connected to the access point
	return []string{}
}

func showClients(clients []string) {
	fmt.Println("Available clients:")
	for _, client := range clients {
		fmt.Println("\t", client)
	}
}

func AskClient(clients []string) string {
	showClients(clients)
	choice := ""
	for choice == "" {
		choice = userIO.Prompt("Select a client: ")
		if choice == "" {
			// return to previous line
			fmt.Print("\033[F")
		}
	}
	return choice
}

// create and send the deauth packet
func Deauth(i iface, ap string, client string) {
	// TODO create and send the deauth packet
}

// reset the interface to normal mode
func (i iface) Reset() {
	// TODO reset the interface to normal mode
}
