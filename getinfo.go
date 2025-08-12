package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/oschwald/geoip2-golang"
	"github.com/redis/go-redis/v9"
)

type FiveTuple struct {
	Protocol     string  `json:"protocol"`
	App          string  `json:"app"`
	SrcIP        string  `json:"src_ip"`
	SrcPort      uint16  `json:"src_port"`
	SrcLocation  string  `json:"src_location"`
	SrcLat       float64 `json:"src_lat"`
	SrcLon       float64 `json:"src_lon"`
	DstIP        string  `json:"dst_ip"`
	DstPort      uint16  `json:"dst_port"`
	DstLocation  string  `json:"dst_location"`
	DstLat       float64 `json:"dst_lat"`
	DstLon       float64 `json:"dst_lon"`
}

func main() {
	ctx := context.Background()

	rdb := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
	sub := rdb.Subscribe(ctx, "raw_packet_channel")

	_, err := sub.Receive(ctx)
	if err != nil {
		log.Fatalf("Subscription failed: %v", err)
	}
	ch := sub.Channel()

	db, err := geoip2.Open("/FinalProject/tmp/info/GeoLite2-City.mmdb")
	if err != nil {
		log.Fatalf("Error opening GeoLite2 database: %v", err)
	}
	defer db.Close()

	fmt.Println("Subscribed... waiting for packets")

	for msg := range ch {
		data, err := base64.StdEncoding.DecodeString(msg.Payload)
		if err != nil {
			log.Printf("base64 decode failed: %v", err)
			continue
		}

		if len(data) < 34 {
			continue
		}

		ethType := binary.BigEndian.Uint16(data[12:14])
		if ethType != 0x0800 {
			continue
		}

		ipHeader := data[14:]
		ipVersion := ipHeader[0] >> 4
		if ipVersion != 4 {
			continue
		}

		ihl := int(ipHeader[0]&0x0F) * 4
		if len(ipHeader) < ihl+4 {
			continue
		}

		proto := ipHeader[9]
		srcIP := net.IP(ipHeader[12:16])
		dstIP := net.IP(ipHeader[16:20])

		if srcIP.Equal(net.IPv4bcast) || dstIP.Equal(net.IPv4bcast) {
			continue
		}
		if isPrivateIP(srcIP) && isPrivateIP(dstIP) {
			continue
		}
		if proto != 6 && proto != 17 {
			continue
		}

		srcLoc, srcLat, srcLon := getGeoLocation(db, srcIP)
		dstLoc, dstLat, dstLon := getGeoLocation(db, dstIP)

		transHeader := ipHeader[ihl:]
		if len(transHeader) < 4 {
			continue
		}

		srcPort := binary.BigEndian.Uint16(transHeader[0:2])
		dstPort := binary.BigEndian.Uint16(transHeader[2:4])
		payload := transHeader[4:]

		payloadStr := ""
		if utf8.Valid(payload) {
			payloadStr = string(payload)
		}

		appProto := DetectApplicationProtocol(proto, srcPort, dstPort, payloadStr)

		tuple := FiveTuple{
			Protocol:     protocolName(proto),
			App:          appProto,
			SrcIP:        srcIP.String(),
			SrcPort:      srcPort,
			SrcLocation:  srcLoc,
			SrcLat:       srcLat,
			SrcLon:       srcLon,
			DstIP:        dstIP.String(),
			DstPort:      dstPort,
			DstLocation:  dstLoc,
			DstLat:       dstLat,
			DstLon:       dstLon,
		}

		jsonData, err := json.Marshal(tuple)
		if err != nil {
			log.Printf("JSON encode error: %v", err)
			continue
		}

		err = rdb.Publish(ctx, "five_tuple_channel", string(jsonData)).Err()
		if err != nil {
			log.Printf("Redis publish failed: %v", err)
		} else {
			fmt.Printf("Published: %s\n", jsonData)
		}
	}
}

func getGeoLocation(db *geoip2.Reader, ip net.IP) (string, float64, float64) {
	if isPrivateIP(ip) {
		return "Private Address", 0.0, 0.0
	}
	record, err := db.City(ip)
	if err != nil {
		log.Printf("Geo lookup failed for %s: %v", ip.String(), err)
		return "Unknown", 0.0, 0.0
	}

	var country, region, city string
	if name, ok := record.Country.Names["en"]; ok {
		country = name
	}
	if len(record.Subdivisions) > 0 {
		if name, ok := record.Subdivisions[0].Names["en"]; ok {
			region = name
		}
	}
	if name, ok := record.City.Names["en"]; ok {
		city = name
	}

	location := strings.Trim(fmt.Sprintf("%s, %s, %s", city, region, country), ", ")
	return location, record.Location.Latitude, record.Location.Longitude
}

func isPrivateIP(ip net.IP) bool {
	privateCIDRs := []*net.IPNet{
		{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
		{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
		{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
	}
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func protocolName(p byte) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown(%d)", p)
	}
}

func DetectApplicationProtocol(proto byte, srcPort, dstPort uint16, data string) string {
	if proto == 6 {
		if isFTP(data, srcPort, dstPort) {
			return "FTP"
		}
		if isSMTP(data, srcPort, dstPort) {
			return "SMTP"
		}
		if isHTTP(data, srcPort, dstPort) {
			return "HTTP"
		}
		return "TCP_CONN"
	} else if proto == 17 {
		if isDNS(srcPort, dstPort) {
			return "DNS"
		}
		return "UDP_PACKET"
	}
	return "UNKNOWN"
}

func isFTP(data string, srcPort, dstPort uint16) bool {
	return srcPort == 21 || dstPort == 21 || strings.HasPrefix(data, "USER ") || strings.HasPrefix(data, "PASS ")
}

func isSMTP(data string, srcPort, dstPort uint16) bool {
	return srcPort == 25 || dstPort == 25 || strings.HasPrefix(data, "HELO") || strings.HasPrefix(data, "MAIL FROM") || strings.HasPrefix(data, "RCPT TO")
}

func isHTTP(data string, srcPort, dstPort uint16) bool {
	return strings.HasPrefix(data, "GET ") || strings.HasPrefix(data, "POST ") || strings.HasPrefix(data, "HEAD ") || strings.Contains(data, "HTTP/")
}

func isDNS(srcPort, dstPort uint16) bool {
	return srcPort == 53 || dstPort == 53
}

