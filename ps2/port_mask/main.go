package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var p_name *string
	var port *uint64
	p_name = flag.String("n", "none", "name of the process to mask port")
	port = flag.Uint64("p", 4040, "port to filter, only that port will be accessable")
	flag.Parse()

	fmt.Printf("masking port: %v of process: %v\n", *port, *p_name)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var obj port_maskObjects
	if err := loadPort_maskObjects(&obj, nil); err != nil {
		log.Fatalf("Error loading objects %v\n", err)
	}
	defer obj.Close()

	// link to interface
	link, err := link.AttachLSM(
		link.LSMOptions{
			Program: obj.ProcessMask,
		})
	if err != nil {
		log.Fatalf("err %v creating link", err)
	}
	defer link.Close()

	var pd port_maskProcessData
	pd.Port = *port
	pd.Comm = stringToInt8Array(*p_name)

	if obj.port_maskMaps.P_data.Put(uint32(0), pd) != nil {
		log.Fatalf("err %v putting val in map", err)
	}

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for range stop {
		fmt.Println("Received Signal")
		return
	}
}

func stringToInt8Array(s string) [16]int8 {
	var arr [16]int8
	for i := 0; i < len(s) && i < 16; i++ {
		arr[i] = int8(s[i])
	}
	return arr
}
