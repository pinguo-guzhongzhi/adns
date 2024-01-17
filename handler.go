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

type cacheItem struct {
	expire int64
	value  interface{}
}

func clearCache() {
	now := time.Now().Unix()
	cache.Range(func(key, value any) bool {
		v := value.(cacheItem)
		if v.expire < now {
			log.Println("deleted cache: ", key)
			cache.Delete(key)
		}
		return true
	})
}

var typeMap = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"TXT":   dns.TypeTXT,
	"CNAME": dns.TypeCNAME,
	"MX":    dns.TypeMX,
	"HTTPS": dns.TypeHTTPS,
}
var typeMapRev = map[uint16]string{}

func init() {
	for k, v := range typeMap {
		typeMapRev[v] = k
	}
	go func() {
		for {
			clearCache()
			time.Sleep(time.Second * 10)
		}
	}()
}

func NewHandler(cfg *Config) (*dnsHandler, error) {
	v := &dnsHandler{
		cfg: cfg,
		pool: sync.Pool{New: func() any {
			c := new(dns.Client)
			c.Timeout = time.Second * 5
			c.UDPSize = 65535
			return c
		}},
		upstream: sync.Map{},
	}
	go v.watch()
	return v, nil
}

type upstream struct {
	server   string
	heatbeat int64
	failed   int // 失败次数
}

func (s *upstream) IsDead() bool {
	return s.failed > 20
}

type dnsHandler struct {
	cfg      *Config
	pool     sync.Pool
	upstream sync.Map
}

func (h *dnsHandler) watch() {
	upstreams := make([]*upstream, 0, len(h.cfg.Servers))
	for _, server := range h.cfg.Servers {
		upstreams = append(upstreams, &upstream{
			server: server,
		})
	}
	c := h.pool.Get().(*dns.Client)
	loop := func() {
		for _, up := range upstreams {
			if up.IsDead() {
				log.Println("upstream check", up.server, "is dead")
				continue
			}
			in, _, err := c.Exchange(&dns.Msg{
				Question: []dns.Question{
					{
						Name:   "www.baidu.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			}, up.server)
			log.Println("upstream check", up.server, up.failed, err)
			up.heatbeat = time.Now().Unix()
			_, ok := h.upstream.Load(up.server)
			if in != nil && len(in.Answer) > 0 {
				up.failed = 0
				h.upstream.Store(up.server, up)
			} else {
				up.failed += 1
				if ok && up.failed >= 5 {
					h.upstream.Delete(up.server)
				}
			}
		}
	}
	for {
		loop()
		time.Sleep(10 * time.Second)
	}
}

func (h *dnsHandler) resolve(domain string, qtype uint16) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := h.pool.Get().(*dns.Client)
	in := []dns.RR{}
	h.upstream.Range(func(key, value any) bool {
		up := value.(*upstream)
		{
			rs, _, err := c.Exchange(m, up.server)
			if err != nil {
				log.Println(domain, qtype, err)
				return true
			}
			for _, ans := range rs.Answer {
				log.Println("  ", ans)
			}
			in = rs.Answer
			return false
		}
	})
	return in
}

func (h *dnsHandler) match(question dns.Question) (*Record, error) {

	for _, domain := range h.cfg.Domains {
		if !strings.Contains(question.Name, domain.Name) {
			continue
		}
		if _, ok := typeMapRev[question.Qtype]; !ok {
			log.Printf("unsupport type: %d", question.Qtype)
			continue
		}
		for _, r := range domain.Records {
			qName := fmt.Sprintf("%s.%s.", r.Name, domain.Name)
			if qName != question.Name {
				if !strings.Contains(r.Name, "*") {
					if qName != question.Name {
						continue
					}
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

			t, ok := typeMap[r.Type]
			if !ok {
				continue
			}
			if t == question.Qtype {
				return &r, nil
			}
			isSame := (question.Qtype != dns.TypeA || question.Qtype != dns.TypeAAAA || question.Qtype != dns.TypeMX) && t == dns.TypeCNAME
			if isSame {
				return &r, nil
			}
		}
	}
	return nil, fmt.Errorf("not matched")
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	handleLocal := func(question dns.Question) ([]dns.RR, bool) {
		r, err := h.match(question)
		if err != nil {
			return nil, false
		}
		switch typeMap[r.Type] {
		case dns.TypeA:
			a := &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: r.TTL},
				A:   net.ParseIP(r.Value),
			}
			return []dns.RR{a}, true
		case dns.TypeAAAA:
			a := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: r.TTL},
				AAAA: net.ParseIP(r.Value),
			}
			return []dns.RR{a}, true
		case dns.TypeMX:
			a := &dns.MX{
				Hdr:        dns.RR_Header{Name: question.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: r.TTL},
				Preference: r.Preference,
				Mx:         r.Value,
			}
			return []dns.RR{a}, true
		case dns.TypeCNAME:
			a := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: r.TTL},
				Target: strings.TrimSuffix(r.Value, ".") + ".",
			}
			return []dns.RR{a}, true
		case dns.TypeHTTPS:
			a := new(dns.HTTPS)
			a.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
			e := new(dns.SVCBAlpn)
			e.Alpn = strings.Split(r.Value, ",")
			// []string{"h2", "http/1.1"}
			a.Value = append(a.Value, e)
			return []dns.RR{a}, true
		default:
			log.Println("invalid type: " + question.String())
		}

		return nil, false
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	for _, question := range r.Question {
		log.Println(question.String())
		log.Printf("Received query: %s, remote=%s\n", question.String(), w.RemoteAddr().String())

		cacheKey := fmt.Sprintf("%s-%d", question.Name, question.Qtype)

		v, ok := cache.Load(cacheKey)

		if ok {
			cacheValue := v.(cacheItem).value.([]dns.RR)
			log.Println("from cache", cacheKey)
			msg.Answer = append(msg.Answer, cacheValue...)
			if len(cacheValue) > 0 {
				continue
			}
		}
		var answers []dns.RR
		if answers, ok = handleLocal(question); !ok {
			answers = h.resolve(question.Name, question.Qtype)
		}
		if len(answers) > 0 {
			ttl := int64(answers[0].Header().Ttl)
			log.Println("save cache:", cacheKey, "ttl", ttl)
			cache.Store(cacheKey, cacheItem{
				expire: time.Now().Unix() + ttl,
				value:  answers,
			})
		}
		msg.Answer = append(msg.Answer, answers...)
	}
	err := w.WriteMsg(msg)
	if err != nil {
		log.Printf("write response error: %s", err.Error())
	}
}
