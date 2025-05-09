package main

import (
	"fmt"
	"log"
	"time"

	"github.com/elliotchance/orderedmap/v3"
)

func printTime(key string, t time.Time) {
	// 计算时间差
	tc := time.Since(t)
	if tc > time.Second*3 {
		log.Printf("运行过长:%s - %s\n", key, fmt.Sprintf("%s", tc))
	}
}

// 直接获取所有值的切片
func GetValuesSlice(om *orderedmap.OrderedMap[string, ProxyIp]) []ProxyIp {
	values := make([]ProxyIp, 0, om.Len())
	for value := range om.Values() {
		values = append(values, value)
	}
	return values
}
