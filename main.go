package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
    "hash/fnv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
)

var ignore []*net.IPNet
var privateIPBlocks []*net.IPNet
var SERVER_IP *string
var input = make(chan []byte)
var status = make(chan []byte)
var hostname, _ = os.Hostname()
var connIP string
var hostHash string

func main() {
    SERVER_IP = flag.String("server", "", "Server IP")
    flag.Parse()

	f, err := os.OpenFile("network-agent.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	for _, cidr := range []string{
		"224.0.0.0/3",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("parse error on %q: %v", cidr, err)
		}
		ignore = append(ignore, block)
	}

	for _, cidr := range []string{
	    "10.0.0.0/8",
        "172.12.0.0/12",
        "192.168.0.0/16",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("parse error on %q: %v", cidr, err)
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}

	log.Println("Starting up...")

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Println(err)
	}


    hostHash = fmt.Sprint(hash(hostname))
    RegisterAgent()

    conn := initializeWebSocket(*SERVER_IP)
    defer conn.Close()
    statusConn := initializeStatusWebSocket(*SERVER_IP)
    defer statusConn.Close()

    connIP = strings.Split(conn.LocalAddr().String(), ":")[0]

    go checkin()

	for _, device := range ifaces {
		log.Printf("Interface Name: %s", device.Name)
		go capturePackets(device.Name)
	}

    for {
        select {
            case t := <-input:
                err := conn.WriteMessage(websocket.TextMessage, t)
                if err != nil {
                    log.Println(err)
                    return
                }

            case t := <-status:
                err := statusConn.WriteMessage(websocket.TextMessage, t)
                if err != nil {
                    log.Println(err)
                    return
                }
        }
    }
}

func capturePackets(iface string) {
	if !isInterfaceUp(iface) {
		log.Printf("Interface is down: %s", iface)
		return
	}

	log.Println("Capturing packets on interface: ", iface)
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Println(err)
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

			if !ipIsInBlock(dstIP, privateIPBlocks) || ipIsInBlock(srcIP, ignore) || ipIsInBlock(dstIP, ignore) || dstIP == *SERVER_IP || srcIP == *SERVER_IP {
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
				log.Println(err)
			}

			if dstPort > 30000 {
				continue
			}

			host := interface{}(map[string]interface{}{
				"Src":  srcIP,
				"Dst":  dstIP,
				"Port": dpt,
			})

			jsonData, err := json.Marshal(host)
			if err != nil {
				log.Println(err)
			}

            input <- jsonData
		}
	}
}

func ipIsInBlock(ip string, block []*net.IPNet) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		log.Println("Invalid IP address")
		return false
	}
	for _, block := range block {
		if block.Contains(ipAddr) {
			return true
		}
	}
	return false
}

func isInterfaceUp(interfaceName string) bool {
	if runtime.GOOS == "windows" {
		return true
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Printf("Error getting interface %s: %s", interfaceName, err)
		return false
	}
	return iface.Flags&net.FlagUp != 0
}

func initializeWebSocket(server string) *websocket.Conn {
    log.Println("Initializing WebSocket...")
    url := url.URL{Scheme: "ws", Host: server, Path: "/ws"}
    conn, _, err := websocket.DefaultDialer.Dial(url.String(), nil)
    if err != nil {
        log.Println(err)
    }
    return conn
}

func initializeStatusWebSocket(server string) *websocket.Conn {
    log.Println("Initializing status WebSocket...")
    url := url.URL{Scheme: "ws", Host: server, Path: "/ws/agent/status"}
    conn, _, err := websocket.DefaultDialer.Dial(url.String(), nil)
    if err != nil {
        log.Println(err)
    }
    return conn
}

func RegisterAgent() {
    log.Println("Registering agent...")

    hostOS := runtime.GOOS

    host := interface{}(map[string]interface{}{
        "ID": fmt.Sprint(hostHash),
        "Hostname": hostname,
        "HostOS": hostOS,
    })

    jsonData, err := json.Marshal(host)
    if err != nil {
        log.Println(err)
    }

    fmt.Println(string(jsonData))

    _, err = http.Post("http://"+*SERVER_IP+"/api/agents/add", "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        log.Println(err)
    }
}

func checkin() {
    ping := []byte(fmt.Sprintf(`{"ID": %s, "Status": "Alive"}`, hostHash))
    for {
        status <- ping
        time.Sleep(2 * time.Second)
    }
}

func hash(s string) uint32 {
    h := fnv.New32a()
    h.Write([]byte(s))
    return h.Sum32()
}
