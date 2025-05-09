package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elliotchance/orderedmap/v3"
	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
)

var verifyIS = false
var ProxyPool = orderedmap.NewOrderedMap[string, ProxyIp]()
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
	fmt.Printf("\r代理验证中: %d  成功:%d  验证中:%d ", count, ProxyPool.Len(), checkCount)
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
	err := VerifyAllV2(pi)
	if err == nil {
		if !first {
			IPDelVal(pi)
			return
		}
	}

	pi.RequestNum = 1
	pi.SuccessNum = 1
	IPAdd(pi)
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
func VerifyAllV2(pi *ProxyIp) (err error) {
	timeout := time.Duration(conf.Config.VerifyTimeout) * time.Second
	client := req.C().
		ImpersonateChrome().
		EnableInsecureSkipVerify().
		DisableKeepAlives().
		SetTimeout(timeout)
	startTime := time.Now()
	defer func() {
		//计算请求时间
		tc := time.Since(startTime)
		pi.Time = time.Now().Format("2006-01-02 15:04:05")
		pi.Speed = fmt.Sprintf("%s", tc)
		printTime("verify2", startTime)
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

func VerifyProxy() {
	if run {
		log.Println("代理抓取中, 无法进行代理验证")
		return
	}
	verifyIS = true

	log.Printf("开始验证代理存活情况, 验证次数是当前代理数的5倍: %d\n", ProxyPool.Len())
	for v := range ProxyPool.Values() {
		v.RequestNum = 0
		v.SuccessNum = 0
		wg3.Add(1)
		ch1 <- 1
		go Verify(&v, &wg3, ch1, false)
	}
	wg3.Wait()
	lock.Lock()
	export()
	lock.Unlock()
	log.Printf("\r%s 代理验证结束, 当前可用IP数: %d\n", time.Now().Format("2006-01-02 15:04:05"), ProxyPool.Len())
	verifyIS = false
}

func IPAdd(pi *ProxyIp) {
	lock.Lock()
	defer lock.Unlock()
	// log.Println("添加IP到代理池", pi.Ip+":"+pi.Port)
	ProxyPool.Set(pi.Ip+":"+pi.Port, *pi)
}

func IPDel(key string) bool {
	lock.Lock()
	defer lock.Unlock()
	return ProxyPool.Delete(key)
}

func IPDelVal(pi *ProxyIp) bool {
	key := pi.Ip + ":" + pi.Port
	return IPDel(key)
}
