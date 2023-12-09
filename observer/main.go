package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	mp "github.com/tom--bo/mysql-packet-deserializer"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	debug      bool
	prof       bool
	cpuRate    int
	name       string
	els        bool   = false
	timeLayout string = "2006-01-02 15:04:05.000000"
	readOnly   bool   = true

	device      string
	snapshotLen int
	promiscuous bool
	handle      *pcap.Handle
	packetCount int

	ignoreHostStr string
	ignoreHosts   []string
	mPort         int

	rHost     string
	rPort     int
	rPassword string
	pcapFile  string

	eHost   string
	ePort   int
	eUser   string
	ePasswd string

	rPool   *redis.Pool
	eClient *http.Client
)

type MySQLPacketInfo struct {
	srcIP        string
	srcPort      int
	dstIP        string
	dstPort      int
	mysqlPacket  []mp.IMySQLPacket
	capturedTime time.Time
}

func parseOptions() {
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.BoolVar(&prof, "prof", false, "prof")
	flag.StringVar(&pcapFile, "f", "", "pcap file. this option invalid packet capture from devices.")
	flag.IntVar(&packetCount, "c", -1, "Limit processing packets count (only enable when -debug is also specified)")
	flag.StringVar(&name, "name", "", "process name which is used as prefix of redis key")
	flag.IntVar(&cpuRate, "cpu-rate", 2, "This is experimental option, It is NOT recommended to use this! goroutine rate for CPUs, specify the doubled rate which you want to specify")

	// gopacket
	flag.StringVar(&device, "d", "en0", "device name to capture.")
	flag.IntVar(&snapshotLen, "s", 1024, "snapshot length for gopacket")
	flag.BoolVar(&promiscuous, "pr", false, "promiscuous for gopacket")

	// MySQL
	flag.StringVar(&ignoreHostStr, "ih", "localhost", "ignore mysql hosts, specify only one ip address")
	flag.IntVar(&mPort, "mP", 0, "mysql port")

	// Redis
	flag.StringVar(&rHost, "rh", "localhost", "redis host")
	flag.IntVar(&rPort, "rP", 6379, "redis port")
	flag.StringVar(&rPassword, "rp", "", "redis password")

	// Elasticsearch
	flag.StringVar(&eHost, "eh", "", "Elasticsearch host")
	flag.IntVar(&ePort, "eP", 9200, "Elasticsearch port")
	flag.StringVar(&eUser, "eu", "", "Elasticsearch user (only for basic authentication)")
	flag.StringVar(&ePasswd, "ep", "", "Elasticsearch passwd (only for basic authentication)")

	flag.Parse()
}

func newPool(addr string, cpus int) *redis.Pool {
	if rPassword != "" {
		return &redis.Pool{
			MaxIdle:     cpus,
			MaxActive:   0,
			Wait:        true,
			IdleTimeout: 10 * time.Second,
			Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", addr, redis.DialPassword(rPassword)) },
		}
	}
	return &redis.Pool{
		MaxIdle:     cpus,
		MaxActive:   0,
		Wait:        true,
		IdleTimeout: 10 * time.Second,
		Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
	}
}

func getMySQLPacketInfo(packet gopacket.Packet) (MySQLPacketInfo, error) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return MySQLPacketInfo{}, errors.New("invalid packets")
	}

	frame := packet.Metadata()
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return MySQLPacketInfo{}, errors.New("Invalid_Packet")
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)
	mcmd := mp.DeserializePacket(applicationLayer.Payload())
	if len(mcmd) == 0 {
		return MySQLPacketInfo{}, errors.New("Not_MySQL_Packet")
	}
	return MySQLPacketInfo{ip.SrcIP.String(), int(tcp.SrcPort), ip.DstIP.String(), int(tcp.DstPort), mcmd, frame.CaptureInfo.Timestamp}, nil
	// return MySQLPacketInfo{"srcIP", int(tcp.SrcPort), "dstIP", int(tcp.DstPort), mcmd, frame.CaptureInfo.Timestamp}, nil
}

func checkReadQuery(q string) bool {
	q = strings.TrimSpace(q)
	if strings.HasPrefix(q, "select") || strings.HasPrefix(q, "SELECT") {
		return true
	}
	return false
}

// when debug
func writeQueriesToFile(packet gopacket.Packet, cnt int) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		pInfo, err := getMySQLPacketInfo(packet)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Printf("%4d, %26s, %-10s: ", cnt, pInfo.capturedTime.Format(timeLayout), pInfo.mysqlPacket[0].GetCommandType())
		/*
			j, err := json.Marshal(pInfo.mysqlPacket)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(j))
		*/
	}
}

func isIgnoreHosts(ip string, ignoreHosts []string) bool {
	for _, h := range ignoreHosts {
		if ip == h {
			return true
		}
	}
	return false
}

// to redis
func sendQuery(packet gopacket.Packet) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		pInfo, err := getMySQLPacketInfo(packet)
		if err != nil {
			fmt.Println(err)
			return
		}
		if isIgnoreHosts(pInfo.srcIP, ignoreHosts) {
			return
		}

		key := name + ":" + pInfo.srcIP + ":" + strconv.Itoa(pInfo.srcPort)
		capturedTime := strconv.Itoa(int(pInfo.capturedTime.UnixNano() / 1000)) // Need to be shorter than eq 15 char and also can't get time in nano sec
		val := ""

		if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_QUERY {
			cmd := pInfo.mysqlPacket[0].(mp.ComQuery)
			q := makeOneLine(cmd.Query)
			if readOnly && !checkReadQuery(q) {
				return
			}
			val = "Q;" + capturedTime + ";" + q
		} else if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_STMT_PREPARE {
			cmd := pInfo.mysqlPacket[0].(mp.ComSTMTPrepare)
			q := makeOneLine(cmd.Query)
			if readOnly && !checkReadQuery(q) {
				return
			}
			val = "P;" + capturedTime + ";" + q
			// ?? need to add statementId in return packet
		} else if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_STMT_EXECUTE {
			cmd := pInfo.mysqlPacket[0].(mp.ComSTMTExecute)
			val = "E;" + capturedTime + ";" + strconv.Itoa(cmd.STMTID) + ";" + cmd.ValueOfEachParameter
		} else if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_STMT_FETCH {
			cmd := pInfo.mysqlPacket[0].(mp.ComSTMTFetch)
			val = "F;" + capturedTime + ";" + strconv.Itoa(cmd.STMTID) + ";" + strconv.Itoa(cmd.NumRows)
		} else if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_STMT_SEND_LONG_DATA {
			// TBD
		} else if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_STMT_RESET {
			// TBD
		} else if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_STMT_CLOSE {
			// TBD
		} else {
			return
		}
		c := rPool.Get()
		_, err = c.Do("RPUSH", key, val)

		if err != nil {
			panic(err)
		}
		c.Close()
	}
}

func makeOneLine(q string) string {
	q = strings.Replace(q, "\"", "'", -1)
	q = strings.Replace(q, "\n", " ", -1)

	return q
}

type Capture struct {
	Time    time.Time `json:"time"`
	SrcIP   string    `json:"src_ip"`
	SrcPort int       `json:"src_port"`
	DstIP   string    `json:"dst_ip"`
	DstPort int       `json:"dst_port"`
	Query   string    `json:"query"`
}

// to Elasticsearch
func sendQueryToElasticsearch(packet gopacket.Packet) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		pInfo, err := getMySQLPacketInfo(packet)
		if err != nil {
			fmt.Println(err)
			return
		}

		q := ""
		if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_QUERY {
			cmd := pInfo.mysqlPacket[0].(mp.ComQuery)
			q = cmd.Query
		} else {
			return
		}

		c := Capture{
			Time:    pInfo.capturedTime,
			SrcIP:   pInfo.srcIP,
			SrcPort: pInfo.srcPort,
			DstIP:   pInfo.dstIP,
			DstPort: pInfo.dstPort,
			Query:   q,
		}
		jsonString, _ := json.Marshal(c)
		if debug {
			fmt.Println(string(jsonString))
		}

		if eHost == "0.0.0.0" {
			return
		}

		var req *http.Request

		if eUser != "" {
			// ?? need to be fixed (https)
			req, err = http.NewRequest(
				"POST",
				"https://"+eHost+":"+strconv.Itoa(ePort)+"/mqr/query",
				bytes.NewBuffer(jsonString),
			)
			auth := eUser + ":" + ePasswd
			req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		} else {
			req, err = http.NewRequest(
				"POST",
				"http://"+eHost+":"+strconv.Itoa(ePort)+"/mqr/query",
				bytes.NewBuffer(jsonString),
			)
		}
		if err != nil {
			panic(err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := eClient.Do(req)
		if err != nil {
			panic(err)
		}
		_, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		resp.Body.Close()
	}
}

func main() {
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 1000

	parseOptions()
	if prof {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}
	ignoreHosts = strings.Split(ignoreHostStr, ",")

	// redis client
	cpus := runtime.NumCPU() * cpuRate / 2 // Need to experimentations
	var err error
	if !debug {
		redisHost := rHost + ":" + strconv.Itoa(rPort)
		rPool = newPool(redisHost, cpus)
	}
	if eHost != "" {
		els = true
		if eHost != "0.0.0.0" {
			eClient = &http.Client{}
		}
	}

	if pcapFile != "" {
		// Open from pcap file
		handle, err = pcap.OpenOffline(pcapFile)
	} else {
		// Open device
		ihandler, _ := pcap.NewInactiveHandle(device)
		ihandler.SetBufferSize(2147483648)
		ihandler.SetSnapLen(snapshotLen)
		ihandler.SetTimeout(pcap.BlockForever)
		ihandler.SetPromisc(promiscuous)
		handle, err = ihandler.Activate()
	}
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	filter := "tcp and tcp[13] & 8 != 0" // tcp PSH flag is set (more smart filtering needed!)
	if mPort != 0 {
		filter += " and port " + strconv.Itoa(mPort)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		panic(err)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	semaphore := make(chan bool, cpus)

	if els { // to Elasticsearch both debug = ON/OFF
		cnt := 0
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Println(err)
				continue
			}

			semaphore <- true
			go func() {
				defer func() { <-semaphore }()
				sendQueryToElasticsearch(packet)
			}()

			if packetCount != -1 {
				if cnt > packetCount {
					break
				}
				cnt++
			}
		}
	} else if debug { // only debug option specified, write packet-data to file
		cnt := 0
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Println(err)
				continue
			}

			semaphore <- true
			go func() {
				defer func() { <-semaphore }()
				writeQueriesToFile(packet, cnt)
			}()

			if packetCount != -1 {
				if cnt > packetCount {
					break
				}
				cnt++
			}
		}
	} else { // Not debug either elasticsearch. Add redis as fast as possible
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Println(err)
				continue
			}
			semaphore <- true
			go func() {
				defer func() { <-semaphore }()
				sendQuery(packet)
			}()
		}
	}
}
