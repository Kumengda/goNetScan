package netScan

import "encoding/binary"

func checksum(data []byte) (uint16, error) {
	sum := 0
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) {
			// 奇数个字节，最后一个字节填0
			sum += int(data[i])
		} else {
			sum += int(data[i])<<8 | int(data[i+1])
		}
	}

	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	return uint16(^sum), nil
}
func getPortByte(port int) []byte {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	return portBytes
}
func getTcpHeader(port int) []byte {
	tcpHeader := make([]byte, 20)
	// 源端口
	copy(tcpHeader[0:2], []byte{0x12, 0x34})
	// 目标端口
	copy(tcpHeader[2:4], getPortByte(port))
	// 序列号
	copy(tcpHeader[4:8], []byte{0x00, 0x00, 0x00, 0x00})
	// 确认号
	copy(tcpHeader[8:12], []byte{0x00, 0x00, 0x00, 0x00})
	// TCP 头部长度和保留字段
	copy(tcpHeader[12:14], []byte{0x50, 0x02})
	// 窗口大小
	copy(tcpHeader[14:16], []byte{0xFF, 0xFF})
	// 检验和（先填0，后计算）
	copy(tcpHeader[16:18], []byte{0x00, 0x00})
	// 紧急指针
	copy(tcpHeader[18:20], []byte{0x00, 0x00})
	return tcpHeader
}
