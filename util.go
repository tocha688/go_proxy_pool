package main

import (
	"fmt"
	"log"
	"time"
)

func printTime(key string, t time.Time) {
	// 计算时间差
	tc := time.Since(t)
	if tc > time.Second*3 {
		log.Printf("运行过长:%s - %s\n", key, fmt.Sprintf("%s", tc))
	}
}
