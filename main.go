package main

import (
	"fmt"
	"github.com/Kumengda/goNetScan/netScan"
)

func main() {
	scan, err := netScan.NewNetScan("en0", "192.168.2.232", 5, netScan.Fast)
	if err != nil {
		fmt.Println(err)
		return
	}
	synScan, err := scan.SynScan("101.43.226.36", "1-65535")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, v := range synScan {
		fmt.Println(v)
	}

}
