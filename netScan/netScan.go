package netScan

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type NetScan struct {
	fd              int
	networkCardName string
	networkCardIp   string
	lisenStatusChan chan string
	closeTagChan    chan bool
	timeout         int
	openPort        []layers.TCPPort
	speed           Speed
}

func NewNetScan(networkCardName, networkCardIp string, timeout int, speed Speed) (*NetScan, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	return &NetScan{
		networkCardIp:   networkCardIp,
		networkCardName: networkCardName,
		fd:              fd,
		timeout:         timeout,
		lisenStatusChan: make(chan string),
		closeTagChan:    make(chan bool),
		speed:           speed,
	}, nil
}
func (n *NetScan) SynScan(ip string, port string) ([]layers.TCPPort, error) {
	var portList []int
	if strings.Contains(port, "-") {
		start, err := strconv.Atoi(strings.Split(port, "-")[0])
		end, err := strconv.Atoi(strings.Split(port, "-")[1])
		if err != nil {
			return nil, errors.New("port error")
		}
		for i := start; i <= end; i++ {
			portList = append(portList, i)
		}
	}
	go func() {
		n.listenSynPack(ip)
	}()
	for v := range n.lisenStatusChan {
		switch v {
		case START_LISTEN:
			for _, i := range portList {
				n.sendSyncPac(ip, getTcpHeader(i))
				switch n.speed {
				case Fast:
					time.Sleep(time.Microsecond * 10)
				case Medium:
					time.Sleep(time.Microsecond * 100)
				case Slow:
					time.Sleep(time.Millisecond * 1)
				case VerySlow:
					time.Sleep(time.Millisecond * 10)

				}
			}
			time.Sleep(time.Duration(n.timeout) * time.Second)
			n.closeTagChan <- true
		case END_LISTEN:
			close(n.lisenStatusChan)
		default:
			return nil, errors.New(v)
		}
	}
	return n.openPort, nil
}
func (n *NetScan) listenSynPack(dstIp string) {
	handle, err := pcap.OpenLive(n.networkCardName, 1000, true, pcap.BlockForever)
	if err != nil {
		n.lisenStatusChan <- err.Error()
	}
	defer handle.Close()
	bpfFilter := "src host " + dstIp
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		n.lisenStatusChan <- err.Error()
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetsChan := packetSource.Packets()
	n.lisenStatusChan <- START_LISTEN
	for {
		select {
		case pacet := <-packetsChan:
			if pacet == nil {
				continue
			}
			tcpLayer := pacet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				srcPort := tcp.SrcPort
				// 检查是否设置了 ACK 标志
				if tcp.ACK && !tcp.RST {
					n.openPort = append(n.openPort, srcPort)
				}
			}
		case <-n.closeTagChan:
			handle.Close()
			n.lisenStatusChan <- END_LISTEN
		}
	}
}
func (n *NetScan) sendSyncPac(dstIp string, tcpHeader []byte) (err error) {
	// 设置目标地址和端口
	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], net.ParseIP(dstIp).To4())

	// 构建 TCP 伪首部（用于计算校验和）
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], net.ParseIP(n.networkCardIp).To4())
	copy(pseudoHeader[4:8], addr.Addr[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = syscall.IPPROTO_TCP
	pseudoHeader[10] = 0
	pseudoHeader[11] = byte(len(tcpHeader))

	// 计算 TCP 校验和
	checksum, err := checksum(append(pseudoHeader, tcpHeader...))
	if err != nil {
		return err
	}
	copy(tcpHeader[16:18], []byte{byte(checksum >> 8), byte(checksum & 0xFF)})

	// 发送 SYN 报文
	packet := append(tcpHeader)
	if err := syscall.Sendto(n.fd, packet, 0, &addr); err != nil {
		return err
	}
	return nil
}
func (n *NetScan) close() error {
	return syscall.Close(n.fd)
}
