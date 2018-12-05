package ZFinger

import (
	"errors"
	"fmt"
	"github.com/dlclark/regexp2"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
)

type Probe struct {
	Services    []Service `json:"services"`
	HelloString string    `json:"hello_string"`
	Rarity      int       `json:"rarity"`
	Ports       []int     `json:"ports"`
	Scheme      string    `json:"scheme"`
	ProbName    string    `json:"prob_name"`
	SSLPorts    []int     `json:"ssl_ports"` // ports but ssl format.
}

type Service struct {
	MatchType string          `json:"match_type"`
	Name      string          `json:"name"`
	Reg       *regexp2.Regexp `json:"reg"`
	//Reg         string `json:"reg"`
	ServiceInfo string `json:"service_info"` // service info, such as cpe/version info from regexp.
}

func GenService(line string) (service Service, err error) { // 给一个 match/softmatch的行生成 Service Object
	if line[0] == '#' {
		return service, errors.New("Commented line")
	}
	if len(line) == 0 {
		return service, errors.New("Empty line")
	}
	re, err := regexp.Compile(`(?s)(\w+) (.+) \w(\||=|%)(.*?)\|(.*?)$`)
	if err != nil {
		//fmt.Println(err)
		return service, err
	}
	result := re.FindStringSubmatch(line)
	if len(result) < 3 {
		return service, errors.New("gen regexp failed.")
	}
	service.MatchType = result[1]
	service.Name = result[2]
	reg, err := regexp2.Compile(result[4], 0)
	if err != nil {
		//fmt.Println(err)
		return service, errors.New("gen regexp failed.")
	}
	//service.Reg = result[4]
	service.Reg = reg
	service.ServiceInfo = result[len(result)-1]
	return service, nil
}
func GenProbes(line string) (probe Probe, err error) {
	probesRegexp, err := regexp.Compile(`Probe (.*?) (.*?) \w\|(.*?)\|$`)
	if err != nil {
		return probe, err
	}
	result := probesRegexp.FindStringSubmatch(line)
	probe.Scheme = result[1]
	probe.ProbName = result[2]
	probe.HelloString = result[3]
	return probe, nil
}
func CheckLine(line string, err error) {
	if err != nil {
		//fmt.Println("Get ERROR",line, err)
	}
}
func GenPorts(line string) []int { // generate ports list
	ports := []int{}
	for _, fakePorts := range strings.Split(line, ",") {
		if strings.Contains(fakePorts, "-") {
			splited := strings.Split(fakePorts, "-")
			startPort, err := strconv.Atoi(splited[0])
			CheckLine(line, err)
			endPort, err := strconv.Atoi(splited[1])
			CheckLine(line, err)
			var i = startPort;
			for ; i <= endPort; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(fakePorts)
			CheckLine(line, err)
			ports = append(ports, port)
		}
	}
	return ports
}
func ParseNmapServiceProbes(path string) ([]Probe, error) {
	text, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var NewProbe = false
	var probes = []Probe{}
	var LastProbe = Probe{}
	lines := strings.Split(string(text), "\n")
	var i = 0;
	for ; i < len(lines); {
		if strings.HasPrefix(lines[i], "# ") {
			i++
			continue
		}
		if strings.Compare(lines[i], "##############################NEXT PROBE##############################") == 0 {
			NewProbe = true
		}
		if NewProbe {
			LastProbe = Probe{}
			NewProbe = false
			scanExitFlag := false
			for ; !scanExitFlag; {
				i++ // line -> next line
				if i == len(lines) {
					probes = append(probes, LastProbe) // Last probe end. append to probes
					break
				}
				if strings.Compare(lines[i], "##############################NEXT PROBE##############################") == 0 {
					scanExitFlag = true
					i--
					probes = append(probes, LastProbe) // Last probe end. append to probes
					break
				}
				if strings.HasPrefix(lines[i], "#") { // for commented line
					continue
				} else if strings.HasPrefix(lines[i], "Probe") { // for probe line
					LastProbe, err = GenProbes(lines[i])
					if err != nil {
						fmt.Println("error while parsing probe ", lines[i])
					}
					continue
				} else if strings.HasPrefix(lines[i], "rarity") { // for rarity line
					rarity_str := strings.Replace(lines[i], "rarity ", "", -1)
					rarity, err := strconv.Atoi(rarity_str)
					if err != nil {
						//fmt.Println(rarity_str, err)
						fmt.Println("error while parsing rarity", lines[i]) // handle manly
					}
					LastProbe.Rarity = rarity
					continue
				} else if strings.HasPrefix(lines[i], "ports") {
					LastProbe.Ports = GenPorts(strings.Replace(lines[i], "ports ", "", -1))
				} else if strings.HasPrefix(lines[i], "sslports") {
					LastProbe.Ports = GenPorts(strings.Replace(lines[i], "sslports ", "", -1))
				} else if strings.HasPrefix(lines[i], "softmatch") || strings.HasPrefix(lines[i], "match") {
					service, err := GenService(lines[i])
					CheckLine(lines[i], err)
					LastProbe.Services = append(LastProbe.Services, service)
				} else {
					if len(lines[i]) > 0 {
						//fmt.Println("NOHandler ", lines[i])
					}
				}
			}
		} else {
			if strings.HasPrefix(lines[i], "#") || len(lines[i]) == 0 {
				i++
			} else {
				//fmt.Println("do not know what the fuck is:", lines[i])
				i++
			}
		}
	}
	//rtn, err := json.Marshal(probes)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(string(rtn))
	return probes, err
}
