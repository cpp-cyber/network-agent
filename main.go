package main

import (
	"fmt"
    "os"
    "encoding/json"
	"net"
    "bytes"
	"net/http"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

var privateIPBlocks []*net.IPNet

func main() {

	for _, cidr := range []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
	} {
		_, block, err := net.ParseCIDR(cidr)
        if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}

    fmt.Println("Starting up...")

    ifaces, err := pcap.FindAllDevs()
    if err != nil {
        fmt.Println(err)
    }

    for _, device := range ifaces {
        fmt.Println("Interface Name: ", device.Name)
        go capturePackets(device.Name)
    }

    select {}
}

func capturePackets(iface string) {
    if !isInterfaceUp(iface) {
        fmt.Println("Interface is down: ", iface)
        return
    }

    fmt.Println("Capturing packets on interface: ", iface)
    handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
    if err != nil {
        fmt.Println(err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        var srcIP, dstIP string
        var dstPort int

        ethLayer := packet.Layer(layers.LayerTypeEthernet)
        if ethLayer != nil {
            eth, _ := ethLayer.(*layers.Ethernet)
            if net.HardwareAddr(eth.DstMAC).String() == "ff:ff:ff:ff:ff:ff" {
                continue
            }
        }

        packetNetworkInfo := packet.NetworkLayer()
        if packetNetworkInfo != nil {
            srcIP = packetNetworkInfo.NetworkFlow().Src().String()
            dstIP = packetNetworkInfo.NetworkFlow().Dst().String()

            if !isPrivateIP(srcIP) || !isPrivateIP(dstIP) || dstIP == os.Getenv("SERVER_IP") || srcIP == os.Getenv("SERVER_IP") {
                continue
            }

        }

        packetTransportInfo := packet.TransportLayer()
        if packetTransportInfo != nil {

            tcpLayer := packet.Layer(layers.LayerTypeTCP)
            if tcpLayer != nil {
                tcp, _ := tcpLayer.(*layers.TCP)
                if !tcp.SYN && tcp.ACK {
                    continue
                }
            }

            dpt := packetTransportInfo.TransportFlow().Dst().String()

            dstPort, err = strconv.Atoi(dpt)
            if err != nil {
                fmt.Println(err)
            }

            if dstPort > 30000 {
                continue
            } 

            hostname, err := os.Hostname()
            if err != nil {
                fmt.Println(err)
            }

            fmt.Println(hostname)

            host := interface{}(map[string]interface{}{
                "Src": srcIP,
                "Dst": dstIP,
                "Port": dpt,
                "Hostname": hostname,
            })

            jsonData, err := json.Marshal(host)
            if err != nil {
                fmt.Println(err)
            }

            postData := bytes.NewBuffer(jsonData)

            http.Post("http://" + os.Getenv("SERVER_IP") + "/api/connections", "application/json", postData)

        }
    }
}

func isPrivateIP(ip string) bool {

    ipAddr := net.ParseIP(ip)
    if ipAddr == nil {
        fmt.Println("Invalid IP address")
        return false
    }

	for _, block := range privateIPBlocks {
		if block.Contains(ipAddr) {
			return true
		}
	}
	return false
}

func isInterfaceUp(interfaceName string) bool {
    iface, err := net.InterfaceByName(interfaceName)
    if err != nil {
        fmt.Printf("Error getting interface %s: %s", interfaceName, err)
        return false
    }
    return iface.Flags&net.FlagUp != 0
}
