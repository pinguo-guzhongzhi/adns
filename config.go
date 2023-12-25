package main

import (
	"encoding/json"
	"io"
	"os"
)

func loadConf(fileName string) (*Config, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	err = json.Unmarshal(body, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

type Record struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	Preference uint16 `json:"preference"`
}

type Domain struct {
	Name    string   `json:"name"`
	Records []Record `json:"records"`
}

type Config struct {
	Servers []string `json:"servers"` // 转发请求
	Domains []Domain `json:"domains"`
	Cache   struct {
		TTL int `json:"ttl"`
	} `json:"cache"`
}
