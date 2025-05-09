package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"resty.dev/v3"
)

var verifyIS = false
var ProxyPool []ProxyIp
var lock sync.Mutex
var mux2 sync.Mutex
var mux3 sync.Mutex

var count int
var checkCount int

func checkAdd(i int) {
	mux3.Lock()
	checkCount += i
	mux3.Unlock()
}

func countAdd(i int) {
	mux2.Lock()
	count += i
	mux2.Unlock()
}
func countDel(pi *ProxyIp) {
	mux2.Lock()
	fmt.Printf("\r代理验证中: %d  成功:%d  验证中:%d ", count, len(ProxyPool), checkCount)
	count--
	mux2.Unlock()
}
func Verify(pi *ProxyIp, wg *sync.WaitGroup, ch chan int, first bool) {
	checkAdd(1)
	defer func() {
		wg.Done()
		countDel(pi)
		checkAdd(-1)
		<-ch
	}()
	//是抓取验证，还是验证代理池内IP
	err := VerifyAllV3(pi)
	if err == nil {
		if !first {
			return
		}
	}

	pi.RequestNum = 1
	pi.SuccessNum = 1
	PIAdd(pi)
}
func VerifyHttp(pr string) bool {
	proxyUrl, proxyErr := url.Parse("http://" + pr)
	if proxyErr != nil {
		return false
	}
	tr := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	tr.Proxy = http.ProxyURL(proxyUrl)
	client := http.Client{Timeout: time.Duration(conf.Config.VerifyTimeout) * time.Second, Transport: &tr}
	request, err := http.NewRequest("GET", conf.Config.VerifyWeb, nil)
	//处理返回结果
	res, err := client.Do(request)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	// dataBytes, _ := io.ReadAll(res.Body)
	// result := string(dataBytes)
	if res.StatusCode == 200 {
		// if strings.Contains(result, "0;url=http://www.google.com") {
		return true
	}
	return false
}
func VerifyHttps(pr string) bool {
	destConn, err := net.DialTimeout("tcp", pr, 10*time.Second)
	if err != nil {
		return false
	}
	defer destConn.Close()
	req := []byte{67, 79, 78, 78, 69, 67, 84, 32, 119, 119, 119, 46, 98, 97, 105, 100, 117, 46, 99, 111, 109, 58, 52, 52, 51, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58, 32, 119, 119, 119, 46, 98, 97, 105, 100, 117, 46, 99, 111, 109, 58, 52, 52, 51, 13, 10, 85, 115, 101, 114, 45, 65, 103, 101, 110, 116, 58, 32, 71, 111, 45, 104, 116, 116, 112, 45, 99, 108, 105, 101, 110, 116, 47, 49, 46, 49, 13, 10, 13, 10}
	destConn.Write(req)
	bytes := make([]byte, 1024)
	destConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	read, err := destConn.Read(bytes)
	if strings.Contains(string(bytes[:read]), "200 Connection established") {
		return true
	}
	return false
}

func VerifySocket5(pr string) bool {
	destConn, err := net.DialTimeout("tcp", pr, 10*time.Second)
	if err != nil {
		return false
	}
	defer destConn.Close()
	req := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	destConn.Write(req)
	bytes := make([]byte, 1024)
	destConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = destConn.Read(bytes)
	if err != nil {
		return false
	}
	if bytes[0] == 5 && bytes[1] == 255 {
		return true
	}
	return false

}
func Anonymity(pr *ProxyIp, c int) string {
	c++
	host := "http://httpbin.org/get"
	proxy := ""
	if pr.Type == "SOCKET5" {
		proxy = "socks5://" + pr.Ip + ":" + pr.Port
	} else {
		proxy = "http://" + pr.Ip + ":" + pr.Port
	}
	proxyUrl, proxyErr := url.Parse(proxy)
	if proxyErr != nil {
		if c >= 3 {
			return ""
		}
		return Anonymity(pr, c)
	}
	tr := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Timeout: 15 * time.Second, Transport: &tr}
	tr.Proxy = http.ProxyURL(proxyUrl)
	request, err := http.NewRequest("GET", host, nil)
	request.Header.Add("Proxy-Connection", "keep-alive")
	//处理返回结果
	res, err := client.Do(request)
	if err != nil {
		if c >= 3 {
			return ""
		}
		return Anonymity(pr, c)
	}
	defer res.Body.Close()
	dataBytes, _ := io.ReadAll(res.Body)
	result := string(dataBytes)
	if !strings.Contains(result, `"url": "http://httpbin.org/`) {
		if c == 3 {
			return ""
		}
		c++
		return Anonymity(pr, c)
	}
	origin := regexp.MustCompile("(\\d+?\\.\\d+?.\\d+?\\.\\d+?,.+\\d+?\\.\\d+?.\\d+?\\.\\d+?)").FindAllStringSubmatch(result, -1)
	if len(origin) != 0 {
		return "透明"
	}
	if strings.Contains(result, "keep-alive") {
		return "普匿"
	}
	return "高匿"
}
func VerifyAllV3(pi *ProxyIp) (err error) {
	timeout := time.Duration(conf.Config.VerifyTimeout) * time.Millisecond
	client := resty.New().
		SetHeaders(map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
		}).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		//只请求一次不保持连接
		SetTimeout(timeout)
	startTime := time.Now()
	defer func() {
		client.Close()
		//计算请求时间
		tc := time.Since(startTime)
		pi.Time = time.Now().Format("2006-01-02 15:04:05")
		pi.Speed = fmt.Sprintf("%s", tc)
		// if tc > timeout {
		// 	if err != nil {
		// 		log.Println(pi.Ip + " - " + pi.Speed + " Error: " + err.Error())
		// 	} else {
		// 		log.Println(pi.Ip + " - " + pi.Speed)
		// 	}
		// }
	}()
	if pi.Type == "" {
		pi.Type = "http"
	}
	proxy := pi.Type + "://" + pi.Ip + ":" + pi.Port
	client.SetProxy(proxy)

	//处理返回结果
	//https://api1.ip.network/api/json
	//https://demo.ip-api.com/json/?fields=66842623&lang=en
	//
	// res, err := req.R().SetRetryCount(0).Get("https://www.baidu.com")
	res, err := req.R().SetRetryCount(0).Get("https://api1.ip.network/api/json")
	if err != nil {
		// log.Println(pi.Ip + " - " + err.Error())
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return errors.New("Request Error. " + res.Status)
	}
	// log.Println(res.StatusCode)
	result := res.String()
	pi.Country = gjson.Get(result, "country").String()
	pi.Province = gjson.Get(result, "region").String()
	pi.City = gjson.Get(result, "city").String()
	pi.Isp = gjson.Get(result, "meta.isp").String()
	return nil
}
func VerifyAllV2(pi *ProxyIp) (err error) {
	timeout := time.Duration(conf.Config.VerifyTimeout) * time.Millisecond
	client := req.C().
		ImpersonateChrome().
		EnableInsecureSkipVerify().
		DisableKeepAlives().
		// SetDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 	dialer := net.Dialer{
		// 		Timeout: time.Duration(conf.Config.VerifyTimeout) * time.Second,
		// 	}
		// 	return dialer.Dial(network, addr)
		// }).
		SetTimeout(timeout)
	// client.SetIdleConnTimeout(time.Duration(conf.Config.VerifyTimeout) * time.Second)
	// client.SetExpectContinueTimeout(time.Duration(conf.Config.VerifyTimeout) * time.Second)
	// client.SetHTTP2PingTimeout(time.Duration(conf.Config.VerifyTimeout) * time.Second)
	// client.SetTLSHandshakeTimeout(time.Duration(conf.Config.VerifyTimeout) * time.Second)
	// client.SetHTTP2ReadIdleTimeout(time.Duration(conf.Config.VerifyTimeout) * time.Second)
	// client.SetHTTP2WriteByteTimeout(time.Duration(conf.Config.VerifyTimeout) * time.Second)
	// client.SetResponseHeaderTimeout(time.Duration(conf.Config.VerifyTimeout) * time.Second)
	startTime := time.Now()
	defer func() {
		//计算请求时间
		tc := time.Since(startTime)
		pi.Time = time.Now().Format("2006-01-02 15:04:05")
		pi.Speed = fmt.Sprintf("%s", tc)
		if tc > timeout {
			if err != nil {
				log.Println(pi.Ip + " - " + pi.Speed + " Error: " + err.Error())
			} else {
				log.Println(pi.Ip + " - " + pi.Speed)
			}
		}
	}()
	if pi.Type == "" {
		pi.Type = "http"
	}
	proxy := pi.Type + "://" + pi.Ip + ":" + pi.Port
	client.SetProxyURL(proxy)

	//处理返回结果
	//https://api1.ip.network/api/json
	//https://demo.ip-api.com/json/?fields=66842623&lang=en
	//
	res, err := req.R().SetRetryCount(0).Get("https://www.baidu.com")
	// res, err := req.R().SetRetryCount(0).Get("https://api1.ip.network/api/json")
	if err != nil {
		// log.Println(pi.Ip + " - " + err.Error())
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return errors.New("Request Error. " + res.Status)
	}
	// log.Println(res.StatusCode)
	result := res.String()
	pi.Country = gjson.Get(result, "country").String()
	pi.Province = gjson.Get(result, "region").String()
	pi.City = gjson.Get(result, "city").String()
	pi.Isp = gjson.Get(result, "meta.isp").String()
	return nil
}
func VerifyAll(pr string) (string, error) {
	proxy := pr
	client := req.C().
		ImpersonateChrome().
		EnableInsecureSkipVerify().
		DisableKeepAlives().
		SetTimeout(time.Duration(conf.Config.VerifyTimeout) * time.Second)
	if strings.Contains(proxy, "http://") ||
		strings.Contains(proxy, "https://") ||
		strings.Contains(proxy, "socks://") ||
		strings.Contains(proxy, "socks5://") {
		client.SetProxyURL(pr)
	} else {
		client.SetProxyURL("http://" + pr)
	}

	//处理返回结果
	res, err := req.R().Get("http://httpbin.org/get")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return "", errors.New("Request Error. " + res.Status)
	}
	// log.Println(res.StatusCode)
	result := res.String()
	origin := regexp.MustCompile("(\\d+?\\.\\d+?.\\d+?\\.\\d+?,.+\\d+?\\.\\d+?.\\d+?\\.\\d+?)").FindAllStringSubmatch(result, -1)
	if len(origin) != 0 {
		return "透明", nil
	}
	if strings.Contains(result, "keep-alive") {
		return "普匿", nil
	}
	return "高匿", nil
}

func PIAdd(pi *ProxyIp) {
	lock.Lock()
	defer lock.Unlock()
	for i := range ProxyPool {
		if ProxyPool[i].Ip == pi.Ip && ProxyPool[i].Port == pi.Port {
			return
		}
	}
	ProxyPool = append(ProxyPool, *pi)
	ProxyPool = uniquePI(ProxyPool)
}

func VerifyProxy() {
	if run {
		log.Println("代理抓取中, 无法进行代理验证")
		return
	}
	verifyIS = true

	log.Printf("开始验证代理存活情况, 验证次数是当前代理数的5倍: %d\n", len(ProxyPool)*5)
	for i, _ := range ProxyPool {
		ProxyPool[i].RequestNum = 0
		ProxyPool[i].SuccessNum = 0
	}
	count = len(ProxyPool) * 5

	for io := 0; io < 5; io++ {
		for i := range ProxyPool {
			wg3.Add(1)
			ch1 <- 1
			go Verify(&ProxyPool[i], &wg3, ch1, false)
		}
		time.Sleep(15 * time.Second)
	}
	wg3.Wait()
	lock.Lock()
	var pp []ProxyIp
	for i := range ProxyPool {
		if ProxyPool[i].SuccessNum != 0 {
			pp = append(pp, ProxyPool[i])
		}
	}
	ProxyPool = pp
	export()
	lock.Unlock()
	log.Printf("\r%s 代理验证结束, 当前可用IP数: %d\n", time.Now().Format("2006-01-02 15:04:05"), len(ProxyPool))
	verifyIS = false
}

func removeDuplication_map(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		_, ok := set[v]
		if ok {
			continue
		}
		set[v] = struct{}{}
		arr[j] = v
		j++
	}

	return arr[:j]
}
