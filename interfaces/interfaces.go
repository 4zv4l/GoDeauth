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
	Inter *pcap.InactiveHandle
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
	// from string to pcap.IncativeHandle
	for _, inter := range ifacesList {
		if choice == inter.Name {
			i := iface{Name: choice, Inter: CreateInactiveHandle(choice)}
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

func CreateInactiveHandle(name string) *pcap.InactiveHandle {
	iface, err := pcap.NewInactiveHandle(name)
	if err != nil {
		panic(err)
	}
	return iface
}

func (i *iface) SetMonitorMode() error {
	err := i.Inter.SetRFMon(true)
	return err
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
