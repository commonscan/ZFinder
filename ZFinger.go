package ZFinger

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/dlclark/regexp2"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var PluginList []DetectPlugin

type DetectPlugin struct {
	helloStr   []byte
	RegexpList []*regexp.Regexp
	priority   int //priority: from 1 to 100, wil send hello first.
	name       string
}

func init() {
	var redisRegexp = []string{`^-ERR wrong number of arguments for 'get' command\r\n$`,
		`^\$\d+\r\n(?:#[^\r\n]*\r\n)*redis_version:([.\d]+)\r\n`,
		`-ERR operation not permitted\r\n`}
	redisRegexpList := []*regexp.Regexp{}
	for _, i := range redisRegexp {
		redisRegexpList = append(redisRegexpList, regexp.MustCompile(i))
	}
	redisPlugin := DetectPlugin{
		helloStr:   []byte("GET / HTTP/1.0\r\n\r\n"),
		RegexpList: redisRegexpList,
		priority:   0,
		name:       "redis",
	}
	PluginList = append(PluginList, redisPlugin)
}

func Detect(ip, port string) (DetectPlugin, error) {
	conn, err := net.Dial("tcp", ip+":"+port)
	var buffer = make([]byte, 1024)
	if err != nil {
		return DetectPlugin{}, errors.New("connect failed")
	}
	for _, plugin := range PluginList {
		_, err = fmt.Fprint(conn, string(plugin.helloStr))
		if err != nil {
			return DetectPlugin{}, errors.New(err.Error())
		}
		n, err := bufio.NewReader(conn).Read(buffer)
		if err != nil {
			return DetectPlugin{}, errors.New("connect failed")
		}
		for _, regex := range plugin.RegexpList {
			if (regex.Find(buffer[0:n]) != nil) {
				return plugin, nil
			}
		}
	}
	return DetectPlugin{}, errors.New("Do not know")
}

func detectProbe(ip, port string, probe Probe, DefaultServices []Service) {
	p, err := strconv.Atoi(port)
	if IntInSlice(p, probe.Ports) {
		return
	}
	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		return
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.Close()
	var buffer = make([]byte, 1024)
	if err != nil {
		log.Fatal(err)
	}
	probe.HelloString = strings.Replace(probe.HelloString, "\\r", "\r", -1)
	probe.HelloString = strings.Replace(probe.HelloString, "\\n", "\n", -1)
	n, err := conn.Write([]byte(probe.HelloString))
	if err != nil {
		return
	}
	n, err = conn.Read(buffer)
	if err != nil {
		//fmt.Println(err)
		return
	}
	for _, service := range probe.Services {
		if len(service.Reg) == 0 {
			continue
		}
		reg, err := regexp2.Compile(service.Reg, 0)
		if err != nil {
			continue
		}
		if m, _ := reg.FindStringMatch(string(buffer[0:n])); m != nil { //TODO fix here.
			fmt.Println(port, service.Name, service.Reg, "\t", probe.HelloString)
			//for _, i := range m.Groups()[1:] {
			//	fmt.Println(i.String())
			//}
		}
		for _, service := range DefaultServices { // FIXME merge two to one
			if len(service.Reg) == 0 {
				continue
			}
			reg, err := regexp2.Compile(service.Reg, 0) // TODO 可以优化掉，不用每次都重新编译
			if err != nil {
				continue
			}
			if m, _ := reg.FindStringMatch(string(buffer[0:n])); m != nil { //TODO fix here.
				fmt.Println("Port:", port, "Service: ", service.Name, service.Reg)
			}
		}
		//fmt.Println("Get Response", string(buffer[0:n]))
	}
}

func DetectProbe(ip, port string, probe Probe, DefaultServices []Service, wg *sync.WaitGroup) {
	defer wg.Done()
	detectProbe(ip, port, probe, DefaultServices)
}
func IntInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
func RockIT() {
	probs, _ := ParseNmapServiceProbes("nmap-service-probes.txt")
	wg := sync.WaitGroup{}
	port_list := []string{"22", "80", "9929", "31337"}
	//port_list := []string{"22"}
	for _, i := range probs {
		if len(i.HelloString) > 0 {
			for _, j := range port_list {
				wg.Add(1)
				go DetectProbe("45.33.32.156", j, i, probs[0].Services, &wg)
			}
		} else {
			//fmt.Println(i.HelloString, i.ProbName, "skip")
		}
	}
	wg.Wait()
}
