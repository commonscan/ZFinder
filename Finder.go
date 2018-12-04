package ZFinger

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

func SendHelloString(ip, port string, probes []Probe) {
	conn, err := net.DialTimeout("tcp", ip+":"+port, 2*time.Second)
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	defer conn.Close()
	var buffer = make([]byte, 1024)
	if err != nil {
		return
	}
	for _, plugin := range probes {
		if len(plugin.HelloString) > 0 {
			fmt.Println("trying...", plugin.ProbName)
			n, err := conn.Write([]byte(plugin.ProbName))
			fmt.Println(plugin.HelloString)
			if err != nil {
				fmt.Println("write error", err)
				continue
			}
			n, err = bufio.NewReader(conn).Read(buffer)
			if err != nil {
				fmt.Println("read error", err)
				continue
			}
			fmt.Println("BANNER: ", string(buffer[0:n]))
		}
	}
}

func DetectPort() {
	probs, err := ParseNmapServiceProbes("nmap-service-probes.txt")
	if err != nil {
		panic(err)
	}
	SendHelloString("127.0.0.1", "6379", probs)
	//for _, prob := range probs {
	//	fmt.Println(prob.HelloString)
	//}
}
