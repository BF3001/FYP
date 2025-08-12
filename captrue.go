package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/redis/go-redis/v9"
)

// htons converts host byte order to network byte order
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// getActiveInterface selects a physical, up, non-loopback interface
func getActiveInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if (iface.Flags&net.FlagLoopback == 0) &&
			(iface.Flags&net.FlagUp != 0) &&
			!isVirtualInterface(iface.Name) &&
			isPhysicalInterface(iface.Name) {

			addrs, err := iface.Addrs()
			if err == nil && len(addrs) > 0 {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no suitable physical interface found")
}

// 排除常见虚拟网卡名
func isVirtualInterface(name string) bool {
	virtualPrefixes := []string{"docker", "br-", "virbr", "veth", "vmnet", "tun", "tap", "lo"}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// Linux-only: 物理网卡应具有 /sys/class/net/<iface>/device
func isPhysicalInterface(name string) bool {
	path := fmt.Sprintf("/sys/class/net/%s/device", name)
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	iface, err := getActiveInterface()
	if err != nil {
		log.Fatalf("Failed to find active interface: %v", err)
	}
	log.Printf("Using interface: %s", iface.Name)

	// 创建原始 socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("create socket fail: %v", err)
	}
	defer syscall.Close(fd)

	sll := &syscall.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(fd, sll); err != nil {
		log.Fatalf("bind fail: %v", err)
	}

	// 创建 Redis 客户端
	rdb := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
	ctx := context.Background()

	buffer := make([]byte, 65535)
	for {
		n, from, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			log.Printf("recv failed: %v", err)
			continue
		}

		b64Data := base64.StdEncoding.EncodeToString(buffer[:n])
		fmt.Printf("Captured %d bytes from %+v\n", n, from)

		err = rdb.Publish(ctx, "raw_packet_channel", b64Data).Err()
		if err != nil {
			log.Printf("Redis publish failed: %v", err)
		}
	}
}

