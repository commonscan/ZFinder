package ZFinger

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/deckarep/golang-set"
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
	conn, err := net.DialTimeout("tcp", ip+":"+port, 5*time.Second)
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
			if regex.Find(buffer[0:n]) != nil {
				return plugin, nil
			}
		}
	}
	return DetectPlugin{}, errors.New("Do not know")
}

func detectProbe(ip, port string, probe Probe) ([]byte, error) {
	p, err := strconv.Atoi(port)
	if IntInSlice(p, probe.Ports) {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", ip+":"+port, 5*time.Second)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	n, err = conn.Read(buffer)
	if err != nil {
		//fmt.Println(err)
		return nil, err
	} else {
		//fmt.Println(string(buffer[0:n]))
	}
	return buffer[0:n], nil
}

func DetectProbe(ip, port string, probe Probe, conn chan []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	//fmt.Println("Begin ", probe.ProbName, port)
	rtn, err := detectProbe(ip, port, probe)

	if err == nil {
		if rtn != nil {
			conn <- rtn
			//fmt.Println(string(rtn))
		}
		for _, service := range probe.Services {
			if len(rtn) > 0 && service.Reg != nil {
				if isMatch, _ := service.Reg.MatchString(string(rtn)); isMatch {
					fmt.Println("Result-->", service.Name, service.ServiceInfo)
				}
			}
		}
	}
}
func IntInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
func defaultServiceParser(defaultServiceParserConn chan []byte, prob Probe) {
	allBannersSet := mapset.NewSet()
	allBanners := [][]byte{}
	for ; len(defaultServiceParserConn) > 0; {
		buffer := <-defaultServiceParserConn
		if !allBannersSet.Contains(string(buffer)) {
			allBannersSet.Add(string(buffer))
			allBanners = append(allBanners, buffer)
			//fmt.Println("add -->", string(buffer))
		} else {

		}
	}

	for _, i := range allBanners {
		//fmt.Println(string(i))
		for _, service := range prob.Services {
			if len(i) > 0 && service.Reg != nil {
				if isMatch, _ := service.Reg.MatchString(string(i)); isMatch {
					fmt.Println("Result-->", service.Name, service.ServiceInfo)
				}
			}
		}
	}
}
func RockIT() {
	probs, _ := ParseNmapServiceProbes("nmap-service-probes.txt")
	wg := sync.WaitGroup{}
	port_list := []string{"22", "53", "443", "80", "2002"}
	//port_list := []string{"8080"}
	var defaultServiceParserConn = make(chan []byte, 1024)
	//fmt.Println("Begain run")
	for _, i := range probs {
		if len(i.HelloString) > 0 {
			for _, j := range port_list {
				go func(ip, port string, probe Probe, conn chan []byte, wg *sync.WaitGroup) {
					//fmt.Println(ip, port, probe.ProbName, probe.HelloString)
					wg.Add(1)
					DetectProbe(ip, port, probe, conn, wg)
				}("139.199.5.115", j, i, defaultServiceParserConn, &wg)
			}
		} else {
			//fmt.Println(i.HelloString, i.ProbName, "skip")
		}
	}
	wg.Wait()
	fmt.Println("detect End")
	defaultServiceParser(defaultServiceParserConn, probs[0])
}
