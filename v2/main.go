package main

import (
        "fmt"
        "math/rand"
        "net/http"
        "os"
        "regexp"
        "time"
        "io/ioutil"
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

        for _, ip := range ipHistory {
                fmt.Println(ip)
        }
}
