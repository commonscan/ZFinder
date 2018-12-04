package ZFinger

import (
	"fmt"
	"testing"
)

func TestParseNmapServiceProbes(t *testing.T) {
	ParseNmapServiceProbes("./nmap-service-probes.txt")
}
func TestParseNmapServiceProbes2(t *testing.T) {
	ParseNmapServiceProbes("./small_text.txt")
}
func TestGenService(t *testing.T) {
	var TestCase = []string{`match redis m|-ERR operation not permitted\r\n|s p/Redis key-value store/`,
		`match redis m|^\$\d+\r\n(?:#[^\r\n]*\r\n)*redis_version:([.\d]+)\r\n|s p/Redis key-value store/ v/$1/`}
	for _, i := range TestCase {
		_, err := GenService(i)
		if err != nil {
			t.Fatal(err, i)
		}
	}
}

func TestGenProbes(t *testing.T) {
	fmt.Println(GenProbes("Probe TCP ms-sql-s q|\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00|"))
}

func TestGenPorts(t *testing.T) {
	fmt.Println(GenPorts("123,1232,444,0-44"))
}
func TestGenService2(t *testing.T) {
	//fmt.Println(GenService("match impress-remote m|^LO_SERVER_VALIDATING_PIN\n$| p/LibreOffice Impress remote/ cpe:/a:libreoffice:libreoffice/"))
	//GenService(`match ipp m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: CUPS/([-\w_.]+)|s p/CUPS/ v/$1/ cpe:/a:apple:cups:$1/`)
	//GenService(`match http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: TornadoServer/([\w._-]+)\r\n|s p/Tornado httpd/ v/$1/ cpe:/a:tornadoweb:tornado:$1/a`)
	//GenService(`match quake3 m|^\xff\xff\xff\xffstatusResponse\n.*\\version\\([^\\]* linux-[^\\]*)(?=\\).*\\gamename\\baseoa(?=\\)| p/OpenArena game server/ v/$1/ o/Linux/ cpe:/o:linux:linux_kernel/a`)
	GenService(`match http m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: and-httpd|s p/and-httpd/`)
}
