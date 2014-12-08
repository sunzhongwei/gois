package main

import (
	"encoding/json"
	"fmt"

	//"github.com/vially/gois"
	"../../gois"
)

func main() {
	domains := []string{
		"example.com",
		"sunzhongwei.com",
		"yeda.xyz",
	}
	for _, domain := range domains {
		whoisInfo, _ := gois.Whois(domain)
		jsonWhoisInfo, _ := json.MarshalIndent(whoisInfo, "", "    ")
		fmt.Println(string(jsonWhoisInfo))
	}
}
