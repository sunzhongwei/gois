package main

import (
	"fmt"

	//"github.com/vially/gois"
	"../../gois"
)

func main() {
	fmt.Println(gois.Whois("example.com"))
	fmt.Println(gois.Whois("sunzhongwei.com"))
}
