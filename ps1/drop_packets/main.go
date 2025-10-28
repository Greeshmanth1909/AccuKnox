package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// load object
	var portno int64
	flag.Int64Var(&portno, "p", 4040, "The destination port to block all tcp packets")
	flag.Parse()
	fmt.Println(portno)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var obj drop_packetsObjects
	if err := loadDrop_packetsObjects(&obj, nil); err != nil {
		fmt.Printf("Unable to load objects %v\n", err)
		return
	}

	defer obj.Close()

	ifname, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatal("Unable to get interface from name")
	}

	// link to interface
	link, err := link.AttachXDP(
		link.XDPOptions{
			Program:   obj.DropPackets,
			Interface: ifname.Index,
		})
	if err != nil {
		log.Fatalf("err %v creating link", err)
	}
	defer link.Close()

	// add port number to map
	if obj.drop_packetsMaps.GetPort.Put(uint32(0), uint64(portno)) != nil {
		log.Fatalf("err %v putting val in map", err)
	}

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := obj.GetPort.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			//log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}

}
