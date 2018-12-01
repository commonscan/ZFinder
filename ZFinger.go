package ZFinger

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/moovweb/rubex"
	"net"
)

var PluginList []DetectPlugin

type DetectPlugin struct {
	helloStr   []byte
	RegexpList []*rubex.Regexp
	priority   int //priority: from 1 to 100, wil send hello first.
	name       string
}

func init() {
	var redisRegexp = []string{`^-ERR wrong number of arguments for 'get' command\r\n$`,
		`^\$\d+\r\n(?:#[^\r\n]*\r\n)*redis_version:([.\d]+)\r\n`,
		`-ERR operation not permitted\r\n`}
	redisRegexpList := []*rubex.Regexp{}
	for _, i := range redisRegexp {
		redisRegexpList = append(redisRegexpList, rubex.MustCompile(i))
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
