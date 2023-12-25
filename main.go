package main

import (
	"flag"
	"fmt"
	"log"
	"sync"

	"github.com/miekg/dns"
)

var config string

func init() {
	flag.StringVar(&config, "config", "config/prod.json", "配置文件")
}

func main() {
	flag.Parse()
	log.Printf("config file: %s", config)
	cfg, err := loadConf(config)
	if err != nil {
		panic(err)
	}

	handler, err := NewHandler(cfg)
	if err != nil {
		panic(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		udpServer := &dns.Server{
			Addr:      ":53",
			Net:       "udp",
			Handler:   handler,
			UDPSize:   65535,
			ReusePort: true,
		}

		fmt.Println("Starting DNS server on udp port 53")
		err = udpServer.ListenAndServe()
		if err != nil {
			fmt.Printf("Failed to start server: %s\n", err.Error())
		}
	}()
	go func() {
		defer wg.Done()
		udpServer := &dns.Server{
			Addr:      ":53",
			Net:       "tcp",
			Handler:   handler,
			UDPSize:   65535,
			ReusePort: true,
		}
		fmt.Println("Starting DNS server on tcp port 53")
		err = udpServer.ListenAndServe()
		if err != nil {
			fmt.Printf("Failed to start server: %s\n", err.Error())
		}
	}()
	wg.Wait()
}
