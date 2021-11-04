package interfaces

import (
	"bufio"
	"deauth/color"
	"deauth/userIO"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Menu show the menu of the interfaces
func Menu() {
	for {
		choice := userIO.Prompt("(press h for help) " + color.ColorPrint("red", "=> "))
		switch choice {
		case "select":
			iface, err := askInterface()
			if err != nil {
				fmt.Println("err :", err)
			} else {
				InterfaceMenu(iface)
			}
		case "h", "help":
			fmt.Println("select : select an interface")
			fmt.Println("exit   : exit")
		case "exit":
			return
		}
	}
}

// askInterface ask the user to select an interface
func askInterface() (net.Interface, error) {
	ifacesList := GetInterfaces()
	ShowInterfaces(ifacesList)
	choice := ""
	for choice == "" {
		choice = userIO.Prompt(color.ColorPrint("cyan", "interface ") + "=> ")
		if choice == "" {
			fmt.Print("\033[F") // go back to previous line
		}
	}
	// from string to net.interface
	for _, iface := range ifacesList {
		if choice == iface.Name {
			return iface, nil
		}
	}
	return net.Interface{}, errors.New(choice + " : not a valid interface")
}

// InterfaceMenu show the menu of the interface
func InterfaceMenu(iface net.Interface) {
	var listMac []string
	for {
		choice := userIO.Prompt("(" + color.ColorPrint("cyan", iface.Name) + ") ")
		switch choice {
		case "h", "help":
			fmt.Println("show : show the interface")
			fmt.Println("scan : scan the network")
			fmt.Println("deauth : deauth a mac address")
			fmt.Println("exit : exit")
		case "show":
			show(iface)
		case "scan":
			listMac = scanPkg(iface)
		case "deauth":
			mac := selectMac(listMac)
			sendDeauth(iface, mac)
		case "exit":
			return
		}
	}
}

// scanPkg scan the network and print the packets
func scanPkg(iface net.Interface) []string {
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("err :", err)
		return nil
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	macAddrs := []string{}
	c := make(chan string)
	list := make(chan []string)
	go listMac(&macAddrs, c, list)
	go askStop(c)
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		mac := ethernetLayer.(*layers.Ethernet).SrcMAC.String()
		macAddrs = append(macAddrs, mac)
		select {
		case <-c:
			return <-list
		default:
		}
	}
	return nil
}

func askStop(c chan string) {
	scan := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("(press q to stop)")
		scan.Scan()
		if scan.Text() == "q" {
			c <- "stop"
			c <- "stop"
			return
		}
	}
}

func listMac(macAddrs *[]string, c chan string, list chan []string) {
	alreadyIn := []string{}
	for {
		macAddrsWDuplicate := removeDuplicate(*macAddrs)
		if len(*macAddrs) > 0 {
			for _, mac := range macAddrsWDuplicate {
				if !contains(alreadyIn, mac) {
					fmt.Println(color.ColorPrint("red", "mac addresses :"), mac)
					alreadyIn = append(alreadyIn, mac)
				}
			}
		}
		select {
		case <-c:
			list <- alreadyIn
			return
		default:
		}
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func removeDuplicate(s []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range s {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func selectMac(listMac []string) net.HardwareAddr {
	for _, mac := range listMac {
		fmt.Println(color.ColorPrint("green", "=> "), mac)
	}
	choice := userIO.Prompt(color.ColorPrint("red", "mac address ") + "=> ")
	macAddr, err := net.ParseMAC(choice)
	if err != nil {
		fmt.Println("err :", err)
	}
	return macAddr
}

func sendDeauth(iface net.Interface, mac net.HardwareAddr) {
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("err :", err)
		return
	}
	defer handle.Close()
	fmt.Println("sending deauth to", mac)
	sendDeauthPkg(handle, mac)
}

func sendDeauthPkg(handle *pcap.Handle, mac net.HardwareAddr) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       mac,
		EthernetType: layers.EthernetTypeDot1Q,
	}
	gopacket.SerializeLayers(buf, opts, &eth)
	handle.WritePacketData(buf.Bytes())
}

func show(iface net.Interface) {
	fmt.Println("name     :", iface.Name)
	fmt.Println("mac      :", iface.HardwareAddr)
	fmt.Println("flags    :", iface.Flags)
}

func ShowInterfaces(ifaces []net.Interface) {
	for i := range ifaces {
		fmt.Println(color.ColorPrint("green", "\t=>"), ifaces[i].Name)
	}
}

func GetInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("err :", err)
		return nil
	}
	return ifaces
}
