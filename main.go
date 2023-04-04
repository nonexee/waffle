package main

import (
        "context"
        "crypto/tls"
        "fmt"
        "math/rand"
        "net/http"
        "os"
        "regexp"
        "time"
        "io/ioutil"
        "net"
        "github.com/agnivade/levenshtein"
)

func getIPHistory(domain string) ([]string, error) {
    client := &http.Client{}

    req, err := http.NewRequest("GET", fmt.Sprintf("https://viewdns.info/iphistory/?domain=%s", domain), nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("User-Agent", getRandomUserAgent())
    req.Header.Set("Accept-Language", "en-US,en;q=0.9")

    time.Sleep(time.Duration(getRandomDelay()) * time.Millisecond)

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    bodyBytes, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    bodyString := string(bodyBytes)

    ipAddresses := []string{}

    pattern := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
    matches := pattern.FindAllString(bodyString, -1)

    for _, match := range matches {
        ipAddresses = append(ipAddresses, match)
    }

    return ipAddresses, nil
}


func getRandomUserAgent() string {
        userAgents := []string{
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36 Edge/16.16299",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0",
                "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36",
        }
        return userAgents[getRandomInt(len(userAgents))]
}

func getRandomDelay() int {
        return getRandomInt(3000)
}

func getRandomInt(max int) int {
        return rand.Intn(max)
}

func checkCloudflareBypass(ip string, targetDomain string) (bool, error) {
    client := &http.Client{
        Timeout: time.Second * 3,
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                if network == "tcp" {
                    addr = fmt.Sprintf("%s:%s", ip, "443")
                }
                return net.Dial(network, addr)
            },
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }

    req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", targetDomain), nil)
    if err != nil {
        return false, err
    }

    req.Host = targetDomain
    req.Header.Set("User-Agent", getRandomUserAgent())
    req.Header.Set("Accept-Language", "en-US,en;q=0.9")

    resp, err := client.Do(req)
    if err != nil {
        // Check if the error is a timeout error
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            fmt.Printf("%s timed out\n", ip)
        } else if opErr, ok := err.(*net.OpError); ok && opErr.Op == "dial" && opErr.Err.Error() == "connection refused" {
            fmt.Printf("%s connection refused\n", ip)
        } else {
            return false, err
        }
    } else {
        defer resp.Body.Close()

        bodyBytes, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            return false, err
        }

        bodyString := string(bodyBytes)

        // Send a request to the target domain with the specific IP address
        client2 := &http.Client{
            Timeout: time.Second * 3,
            Transport: &http.Transport{
                DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                    if network == "tcp" {
                        addr = fmt.Sprintf("%s:%s", ip, "443")
                    }
                    return net.Dial(network, addr)
                },
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            },
        }
        req2, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", targetDomain), nil)
        if err != nil {
            return false, err
        }
        req2.Host = targetDomain
        req2.Header.Set("User-Agent", getRandomUserAgent())
        req2.Header.Set("Accept-Language", "en-US,en;q=0.9")

        resp2, err := client2.Do(req2)
        if err != nil {
            return false, err
        }
        defer resp2.Body.Close()

        bodyBytes2, err := ioutil.ReadAll(resp2.Body)
        if err != nil {
            return false, err
        }

        bodyString2 := string(bodyBytes2)

        // Compare the response bodies using Levenshtein distance algorithm
        distance := levenshtein.ComputeDistance(bodyString, bodyString2)
        if distance <= 3 {
            return true, nil
        }
    }

    return false, nil
}


func isCloudflareIP(ip string) bool {
    cloudflareIPRanges := []string{
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    }

    for _, ipRange := range cloudflareIPRanges {
        _, subnet, err := net.ParseCIDR(ipRange)
        if err != nil {
            fmt.Println("Error parsing CIDR:", err)
            continue
        }

        if subnet.Contains(net.ParseIP(ip)) {
            return true
        }
    }

    return false
}


func main() {
    if len(os.Args) < 2 {
        fmt.Println("Please provide a target domain as an argument")
        os.Exit(1)
    }

    targetDomain := os.Args[1]
    ipHistory, err := getIPHistory(targetDomain)
    if err != nil {
        fmt.Println("Error:", err)
        os.Exit(1)
    }

    bypassedFound := false

    for _, ip := range ipHistory {
        if isCloudflareIP(ip) {
            //fmt.Printf("%s is a Cloudflare IP, skipping...\n", ip)
            continue
        }

        isBypassed, err := checkCloudflareBypass(ip, targetDomain)
        if err != nil {
            fmt.Println("Error:", err)
            os.Exit(1)
        }

        if isBypassed {
            bypassedFound = true
            fmt.Printf("Possible Cloudflare bypass: %s\n", ip)
        }
    }

    if !bypassedFound {
        fmt.Println("No Cloudflare bypass found")
    }
}
