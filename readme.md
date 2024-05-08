goNetScan 高性能网络扫描器

##### syn tcp扫描

⚠️不支持在windows下运行,因为windows限制了对原始套接字的操作,只能通过libpcap等库对原始链路层进行操作。本项目采用的是原始套接字实现自定义tcp包。



目前支持tcp端口扫描,采用原始套接字(SOCKET_RAW)发送syn包,使用gopacket进行流量监听带有ack标识的数据包。

start:

目前需要指定网卡以及显示声明网卡所对应ip地址,确保路由表中被扫描地址出口网卡为指定网卡

网卡名称和网卡地址均可以通过查询路由表简化为自动处理,这里只是一个最小实现,就没有继续封装了,做显示传入

```golang
func main() {
	scan, err := netScan.NewNetScan("en0", "192.168.2.232", 5, netScan.Fast)
  //这里的第四个参数为扫描速率,有Fast,Medium,Slow,VerySlow暂未开放自定义的速率,其原理就是控制syn发包速率。不同服务器对syn包处理速率有所不同,如果太快可能服务器丢掉很多结果。这里的Fast基本上一瞬间就会发完1-65535的所有syn包,对于本地扫描可以用这个,可以在几秒内扫完所有端口。对于互联网上的公网设备建议使用slow
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
```

