package main

import (
	"fmt"

	"github.com/vially/gois"
)

func main() {
	fmt.Println(gois.Whois("example.com"))
	fmt.Println(gois.Whois("sunzhongwei.com"))
}
