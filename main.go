package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var whitelist = map[string]bool{
	"": true,
}

var blacklist = map[string]bool{
	"": true,
}

func isBlacklisted(ip string) bool {
	return blacklist[ip]
}

func isWhitelisted(ip string) bool {
	return whitelist[ip]
}

func blockIp(ip string) {

	cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		log.Printf("Error blocking IP %s: %v\n", ip, err)
	} else {
		fmt.Printf("Successfully blocked IP %s\n", ip)
	}
}

var synCounts = make(map[string]int)
var synCountsMutex = &sync.Mutex{}

func detectAnomalies(srcIP string) {
	synCountsMutex.Lock()
	defer synCountsMutex.Unlock()
	if !isWhitelisted(srcIP) {
		synCounts[srcIP]++
		if synCounts[srcIP] > 100 {
			if !isBlacklisted(srcIP) {
				blockIp(srcIP)
				fmt.Printf("ALERT: Possible SYN flood detected from IP %s\n", srcIP)
			}
		}
	} else {
		fmt.Printf("Whitelisted IP Request from %s\n", srcIP)
	}
}

func main() {

	// Try to open ip whitelist and blacklist
	err := loadIPListFromFile("whitelist.txt", whitelist)
	if err != nil {
		fmt.Printf("Error loading whitelist: %v\n", err)
	}
	err = loadIPListFromFile("blacklist.txt", blacklist)
	if err != nil {
		fmt.Printf("Error loading blacklist: %v\n", err)
	}

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

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("Shutting down...")
		handle.Close()
		os.Exit(0)
	}()

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
