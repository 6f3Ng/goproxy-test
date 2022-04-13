package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"goproxy-test/goproxy"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type EventHandler struct{}

// 实现证书缓存接口
type Cache struct {
	m sync.Map
}

func (c *Cache) Set(host string, cert *tls.Certificate) {
	c.m.Store(host, cert)
}
func (c *Cache) Get(host string) *tls.Certificate {
	v, ok := c.m.Load(host)
	if !ok {
		return nil
	}

	return v.(*tls.Certificate)
}

func (e *EventHandler) Connect(ctx *goproxy.Context, rw http.ResponseWriter) {
	fmt.Printf("connect to: %s \n", ctx.Req.URL)
	// 保存的数据可以在后面的回调方法中获取
	ctx.Data["req_id"] = "uuid"

	// 禁止访问某个域名
	if strings.Contains(ctx.Req.URL.Host, "example.com") {
		rw.WriteHeader(http.StatusForbidden)
		ctx.Abort()
		return
	}
}

func (e *EventHandler) Auth(ctx *goproxy.Context, rw http.ResponseWriter) {
	fmt.Printf("auth to: %s \n", ctx.Req.URL)
	// 身份验证
}

func (e *EventHandler) BeforeRequest(ctx *goproxy.Context) {
	fmt.Printf("BeforeRequest to: %s \n", ctx.Req.URL)
	// 修改header
	if ctx.Req.Header.Get("Accept-Encoding") != "" {
		ctx.Req.Header.Set("Accept-Encoding", "gzip, deflate")
	} else {
		ctx.Req.Header.Add("Accept-Encoding", "gzip, deflate")
	}
	ctx.Req.Header.Del("If-Modified-Since")
	ctx.Req.Header.Del("If-None-Match")
	ctx.Req.Header.Add("X-Request-Id", ctx.Data["req_id"].(string))
	// 设置X-Forwarded-For
	if clientIP, _, err := net.SplitHostPort(ctx.Req.RemoteAddr); err == nil {
		if prior, ok := ctx.Req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		ctx.Req.Header.Set("X-Forwarded-For", clientIP)
	}
	// 读取Body
	body, err := ioutil.ReadAll(ctx.Req.Body)
	if err != nil {
		// 错误处理
		return
	}
	// Request.Body只能读取一次, 读取后必须再放回去
	// Response.Body同理
	ctx.Req.Body = ioutil.NopCloser(bytes.NewReader(body))

}

func (e *EventHandler) BeforeResponse(ctx *goproxy.Context, resp *http.Response, err error) {
	fmt.Printf("BeforeResponse to: %s \n", ctx.Req.URL.Host)
	if resp == nil {
		return
	}
	// if strings.Contains(ctx.Req.URL.Host, "offlintab.firefoxchina.cn") {
	// 	respBody, _ := ioutil.ReadAll(resp.Body)
	// 	log.Println(string(respBody))
	// 	// respBody = []byte("11223344")
	// 	resp.Body = ioutil.NopCloser(bytes.NewReader(respBody))
	// 	// resp.ContentLength = int64(len(respBody))
	// }
	if strings.Contains(ctx.Req.URL.Host, "api.myip.la") {
		log.Println(resp.Header.Get("Content-Encoding"))
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			log.Println("gzip decode")
			startReader, _ := gzip.NewReader(resp.Body)
			respBody, _ := ioutil.ReadAll(startReader)
			log.Println(string(respBody))
			// respBody = []byte("11223344")
			// var compressData bytes.Buffer
			// startWriter := gzip.NewWriter(&compressData)
			// startWriter.Write(respBody)
			// log.Println(compressData.Bytes())
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(GZIPEn(string(respBody))))
			// resp.ContentLength = int64(len(respBody))
		default:
			log.Println("default")
			respBody, _ := ioutil.ReadAll(resp.Body)
			log.Println(string(respBody))
			// respBody = []byte("11223344")
			resp.Body = ioutil.NopCloser(bytes.NewReader(respBody))
			// resp.ContentLength = int64(len(respBody))
		}
	}
	if err != nil {
		return
	}
	// 修改response
}

// 设置上级代理
func (e *EventHandler) ParentProxy(req *http.Request) (*url.URL, error) {
	fmt.Println("Parent Proxy")
	return nil, nil
	// return url.Parse("socks5://localhost:10808")
	// return url.Parse("http://localhost:8080")
}

func (e *EventHandler) Finish(ctx *goproxy.Context) {
	fmt.Printf("请求结束 URL:%s\n", ctx.Req.URL)
}

// 记录错误日志
func (e *EventHandler) ErrorLog(err error) {
	log.Println(err)
}

//GZIPEn gzip加密
func GZIPEn(str string) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(str)); err != nil {
		panic(err)
	}
	if err := gz.Flush(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

//GZIPDe gzip解密
func GZIPDe(in []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		var out []byte
		return out, err
	}
	defer reader.Close()
	return ioutil.ReadAll(reader)
}

func main() {
	proxy := goproxy.New(goproxy.WithDelegate(&EventHandler{}), goproxy.WithDecryptHTTPS(&Cache{}))
	server := &http.Server{
		Addr:         ":8082",
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
