package main

import (
	"log"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elliotchance/orderedmap/v3"
	"github.com/imroc/req/v3"
)

var wg sync.WaitGroup
var wg2 sync.WaitGroup
var mux sync.Mutex
var ch2 = make(chan int, 50)

// 是否抓取中
var run = false

func spiderRun() {

	run = true
	defer func() {
		run = false
	}()

	count = 0
	log.Println("开始抓取代理...")
	for i := range conf.Spider {
		wg2.Add(1)
		go spider(&conf.Spider[i])
	}
	wg2.Wait()
	log.Printf("\r%s 代理抓取结束           \n", time.Now().Format("2006-01-02 15:04:05"))

	count = 0
	log.Println("开始扩展抓取代理...")
	for i := range conf.SpiderPlugin {
		wg2.Add(1)
		go spiderPlugin(&conf.SpiderPlugin[i])
	}
	wg2.Wait()
	log.Printf("\r%s 扩展代理抓取结束         \n", time.Now().Format("2006-01-02 15:04:05"))
	// count = 0
	// log.Println("开始文件抓取代理...")
	// for i := range conf.SpiderFile {
	// 	wg2.Add(1)
	// 	go spiderFile(&conf.SpiderFile[i])
	// }
	// wg2.Wait()
	// log.Printf("\r%s 文件代理抓取结束         \n", time.Now().Format("2006-01-02 15:04:05"))

	//导出代理到文件
	export()

}

func spider(sp *Spider) {
	defer func() {
		wg2.Done()
		//log.Printf("%s 结束...",sp.Name)
	}()
	//log.Printf("%s 开始...", sp.Name)
	pis := orderedmap.NewOrderedMap[string, ProxyIp]()
	for ui, v := range sp.Urls {
		page := 0
		client := req.C().
			SetCommonHeaders(sp.Headers).
			ImpersonateChrome().
			// SetTLSFingerprint(utls.HelloChrome_131).
			// SetAutoDecodeAllContentType(). //.EnableAutoDecode().
			// DevMode().
			SetTimeout(20 * time.Second)
		for {
			page++
			if ui != 0 {
				time.Sleep(time.Duration(sp.Interval) * time.Second)
			}

			if sp.ProxyIs {
				proxyUrl, parseErr := url.Parse("http://" + conf.Proxy.Host + ":" + conf.Proxy.Port)
				if parseErr != nil {
					log.Println("代理地址错误: \n" + parseErr.Error())
					break
				}
				client.SetProxyURL(proxyUrl.String())
			}
			//替换
			ul := strings.Replace(v, "{page}", strconv.Itoa(page), -1)
			//处理返回结果
			// res, err := client.R().SetMethod(sp.Method).SetURL(ul).Send()
			res, err := client.R().Send(sp.Method, ul)
			if err != nil {
				break
			}
			result := res.String()
			// fmt.Println(result)
			ip := regexp.MustCompile(sp.Ip).FindAllStringSubmatch(result, -1)
			port := regexp.MustCompile(sp.Port).FindAllStringSubmatch(result, -1)
			log.Println(page, "抓取到", len(ip), "/", len(port), "个代理")
			if len(ip) == 0 || len(ip) != len(port) {
				break
			}
			for i := range ip {
				var _ip string
				var _port string
				_ip, _ = url.QueryUnescape(ip[i][1])
				_port, _ = url.QueryUnescape(port[i][1])
				key := _ip + ":" + _port
				if !ProxyPool.Has(key) && !pis.Has(key) {
					pis.Set(key, ProxyIp{Ip: _ip, Port: _port, Source: sp.Name})
				}
			}
			if !strings.Contains(v, "{page}") {
				break
			}
		}
	}
	countAdd(pis.Len())
	for v := range pis.Values() {
		wg.Add(1)
		ch2 <- 1
		go Verify(&v, &wg, ch2, true)
	}
	wg.Wait()

}

func spiderPlugin(spp *SpiderPlugin) {
	defer func() {
		wg2.Done()
	}()
	cmd := exec.Command("cmd.exe", "/c", spp.Run)
	//Start执行不会等待命令完成，Run会阻塞等待命令完成。
	//err := cmd.Start()
	//err := cmd.Run()
	//cmd.Output()函数的功能是运行命令并返回其标准输出。
	buf, err := cmd.Output()
	var pis []ProxyIp
	if err != nil {
		log.Println("失败", spp.Name, err)
	} else {
		line := strings.Split(string(buf), ",")
		for i := range line {
			if !ProxyPool.Has(line[i]) {
				split := strings.Split(line[i], ":")
				pis = append(pis, ProxyIp{Ip: split[0], Port: split[1], Source: spp.Name})
			}
		}
		//var _pis []ProxyIp
		//var pis []ProxyIp
		//var _is = true
		//err = json.Unmarshal(buf, &_pis)
		//if err != nil {
		//	log.Printf("%s 返回值不符合规范\n", spp.Name)
		//	return
		//}
		//for i := range _pis {
		//	for pi := range ProxyPool {
		//		if ProxyPool[pi].Ip == _pis[i].Ip && ProxyPool[pi].Port == _pis[i].Port {
		//			_is = false
		//			break
		//		}
		//	}
		//	if _is {
		//		pis = append(pis, ProxyIp{Ip: _pis[i].Ip, Port: _pis[i].Port, Source: spp.Name})
		//	}
	}
	pis = uniquePI(pis)
	countAdd(len(pis))
	for i := range pis {
		wg.Add(1)
		ch2 <- 1
		go Verify(&pis[i], &wg, ch2, true)
	}
	wg.Wait()
}

// func spiderFile(spp *SpiderFile) {
// 	defer func() {
// 		wg2.Done()
// 	}()
// 	var pis []ProxyIp
// 	fi, err := os.Open(spp.Path)
// 	if err != nil {
// 		log.Println(spp.Name, "失败", err)
// 		return
// 	}
// 	r := bufio.NewReader(fi) // 创建 Reader
// 	for {
// 		_is := true
// 		line, err := r.ReadBytes('\n')
// 		if len(line) > 0 {
// 			split := strings.Split(strings.TrimSpace(string(line)), ":")
// 			// for pi := range ProxyPool {
// 			// 	if ProxyPool[pi].Ip == split[0] && ProxyPool[pi].Port == split[1] {
// 			// 		_is = false
// 			// 		break
// 			// 	}
// 			// }
// 			if _is {
// 				pis = append(pis, ProxyIp{Ip: split[0], Port: split[1], Source: spp.Name})
// 			}
// 		}
// 		if err != nil {
// 			break
// 		}
// 	}
// 	pis = uniquePI(pis)
// 	countAdd(len(pis))
// 	for i := range pis {
// 		wg.Add(1)
// 		ch2 <- 1
// 		go Verify(&pis[i], &wg, ch2, true)
// 	}
// 	wg.Wait()

// }
