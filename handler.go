package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var cache = sync.Map{}

func NewHandler(cfg *Config) (*dnsHandler, error) {
	v := &dnsHandler{
		cfg: cfg,
		pool: sync.Pool{New: func() any {
			c := new(dns.Client)
			c.Timeout = time.Second * 5
			c.UDPSize = 65535
			return c
		}},
	}
	return v, nil
}

type dnsHandler struct {
	cfg  *Config
	pool sync.Pool
}

func (h *dnsHandler) resolve(domain string, qtype uint16) []dns.RR {
	cacheKey := fmt.Sprintf("%s-%d", domain, qtype)
	if v, ok := cache.Load(cacheKey); ok {
		log.Println(domain, "from cache")
		return v.([]dns.RR)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := h.pool.Get().(*dns.Client)
	for _, server := range h.cfg.Servers {
		in, _, err := c.Exchange(m, server)
		if err != nil {
			log.Println(domain, qtype, err)
			continue
		}
		for _, ans := range in.Answer {
			log.Println("\t", ans)
		}
		if len(in.Answer) > 0 {
			cache.Store(cacheKey, in.Answer)
		}
		return in.Answer
	}
	return []dns.RR{}
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	typeMap := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"TXT":   dns.TypeTXT,
		"CNAME": dns.TypeCNAME,
		"MX":    dns.TypeMX,
	}
	typeMapRev := map[uint16]string{}
	for k, v := range typeMap {
		typeMapRev[v] = k
	}

	handleLocal := func(question dns.Question) bool {
		for _, domain := range h.cfg.Domains {
			if !strings.Contains(question.Name, domain.Name) {
				continue
			}
			if _, ok := typeMapRev[question.Qtype]; !ok {
				log.Printf("un support type: %d", question.Qtype)
				continue
			}
			for _, r := range domain.Records {
				t, ok := typeMap[r.Type]
				if !ok {
					continue
				}
				if t != question.Qtype {
					continue
				}
				qName := fmt.Sprintf("%s.%s.", r.Name, domain.Name)
				if qName != question.Name {
					if !strings.Contains(r.Name, "*") {
						continue
					} else {
						tmp := strings.Split(r.Name, "*")
						rName := ""
						if len(tmp) > 1 {
							rName = tmp[1]
						}
						suffix := fmt.Sprintf("%s.%s.", rName, domain.Name)
						if !strings.Contains(question.Name, suffix) {
							continue
						}
					}
				}
				switch question.Qtype {
				case dns.TypeA:
					a := &dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: r.TTL},
						A:   net.ParseIP(r.Value),
					}
					msg.Answer = append(msg.Answer, a)
				case dns.TypeAAAA:
					a := &dns.AAAA{
						Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: r.TTL},
						AAAA: net.ParseIP(r.Value),
					}
					msg.Answer = append(msg.Answer, a)
				case dns.TypeMX:
					a := &dns.MX{
						Hdr:        dns.RR_Header{Name: question.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: r.TTL},
						Preference: r.Preference,
						Mx:         r.Value,
					}
					msg.Answer = append(msg.Answer, a)
				case dns.TypeCNAME:
					a := &dns.CNAME{
						Hdr:    dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: r.TTL},
						Target: r.Value,
					}
					msg.Answer = append(msg.Answer, a)
				default:
					log.Println("invalid type: ")
				}
				return true
			}
		}
		return false
	}

	for _, question := range r.Question {
		log.Println(question.String())
		log.Printf("Received query: %s, remote=%s\n", question.String(), w.RemoteAddr().String())
		if handleLocal(question) {
			continue
		}
		answers := h.resolve(question.Name, question.Qtype)
		msg.Answer = append(msg.Answer, answers...)
	}
	err := w.WriteMsg(msg)
	if err != nil {
		log.Printf("%s", err.Error())
	}
}
