package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var synCounts = make(map[string]int)
var synCountsMutex = &sync.Mutex{}

func detectAnomalies(srcIP string) {
	synCountsMutex.Lock()
	defer synCountsMutex.Unlock()

	synCounts[srcIP]++
	if synCounts[srcIP] > 100 {
		fmt.Printf("ALERT: Possible SYN flood detected from IP %s\n", srcIP)
	}
}

func main() {
	handle, err := pcap.OpenLive("wlo1", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter to capture only TCP packets with SYN flag
	var filter string = "tcp[tcpflags] & tcp-syn != 0"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Capturing TCP SYN traffic...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.SYN && !tcp.ACK {
					detectAnomalies(ip.SrcIP.String())
				}
			}
		}
	}
}
