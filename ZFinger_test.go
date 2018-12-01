package ZFinger

import (
	"fmt"
	"testing"
)

func TestDetect(t *testing.T) {
	plugin, err := Detect("154.8.169.142", "6379")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(plugin.name)
}
