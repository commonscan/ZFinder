package ZFinger

import (
	"fmt"
	"testing"
)

func TestDetect(t *testing.T) {
	plugin, err := Detect("127.0.0.1", "6379")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(plugin.name)
}

func TestRockIT(t *testing.T) {
	RockIT()
}
func TestRockIT2(t *testing.T) {
}
