package gois

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jinzhu/now"
)

var CREATED_ON_KEYWORDS = []string{
	"creation date", // .com, .xyz
	"changed",
	"domain create date",
}
var EXPIRED_ON_KEYWORDS = []string{
	"expiration date",      // .com
	"registry expiry date", // .xyz, e.g. yeda.xyz
}

// Record holds the information returned by the whois server
type Record struct {
	Domain        string
	TrimmedDomain string
	CreatedOn     time.Time
	ExpiredOn     time.Time
	Registered    bool
}

func longestTLDSuffix(domain string) string {
	longestTld := ""
	for tld := range TLDWhoisServers {
		if strings.HasSuffix(domain, "."+tld) && utf8.RuneCountInString(tld) > utf8.RuneCountInString(longestTld) {
			longestTld = tld
		}
	}
	return longestTld
}

func trimSubdomains(domain, tld string) (trimmedDomain string) {
	noTld := strings.TrimSuffix(domain, "."+tld)
	parts := strings.Split(noTld, ".")
	trimmedDomain = fmt.Sprintf("%s.%s", parts[len(parts)-1], tld)
	return trimmedDomain
}

// Whois returns the public whois information for a domain
func Whois(domain string) (record *Record, err error) {
	tld := longestTLDSuffix(domain)
	server := TLDWhoisServers[tld]

	trimmedDomain := trimSubdomains(domain, tld)
	requestDomain := trimmedDomain
	if server == "whois.verisign-grs.com" {
		requestDomain = "=" + trimmedDomain
	} else if server == "whois.denic.de" {
		requestDomain = "-T dn,ace " + trimmedDomain
	}

	response, err := QueryWhoisServer(requestDomain, server)
	if err != nil {
		return
	}

	record, err = parse(response)
	if err == nil {
		record.Domain = domain
		record.TrimmedDomain = trimmedDomain
	}

	return
}

// QueryWhoisServer queries a particular whois server for information about a domain
func QueryWhoisServer(domain, server string) (response string, err error) {
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)
	if buf, err := ioutil.ReadAll(conn); err == nil {
		response = string(buf)
	}

	return
}

// parse whois record
// e.g. created on, expired on
func parse(response string) (record *Record, err error) {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if contains(CREATED_ON_KEYWORDS, strings.ToLower(key)) {
			if parsedDate, parseErr := now.Parse(value); parseErr != nil {
				err = parseErr
			} else {
				record = &Record{CreatedOn: parsedDate, Registered: true}
			}
		}
		if contains(EXPIRED_ON_KEYWORDS, strings.ToLower(key)) {
			if parsedDate, parseErr := now.Parse(value); parseErr != nil {
				err = parseErr
			} else {
				record.ExpiredOn = parsedDate
			}
			return
		}
	}
	return nil, errors.New("Unable to parse whois record")
}

// check whether keyworks slice contains specific keyword
func contains(keywords []string, keyword string) bool {
	for _, value := range keywords {
		if keyword == value {
			return true
		}
	}
	return false
}

func init() {
	now.TimeFormats = append(now.TimeFormats, "02-Jan-2006")
	now.TimeFormats = append(now.TimeFormats, "02-Jan-2006 15:04:05 MST")
	now.TimeFormats = append(now.TimeFormats, "2006-01-02T15:04:05.0Z")
	now.TimeFormats = append(now.TimeFormats, "2006-01-02T15:04:05Z")
	now.TimeFormats = append(now.TimeFormats, "2006-01-02T15:04:05-07:00")
}
