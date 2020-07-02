package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
)

func main() {
	// read VCAP_APP_HOST and PORT env variables set by CloudFoundry / PaaS / K8s
	host := os.Getenv("VCAP_APP_HOST")
	if len(host) == 0 {
		host = "0.0.0.0"
	}
	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
	}
	address := host + ":" + port

	// register proxy
	http.Handle("/", NewProxy())

	log.Printf("Starting proxy demo, listening on [%s] ...\n", address)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Fatal(err)
	}
}

type Proxy struct {
	SkipSSLValidation bool
	ProxyTargetURL    string
}

func NewProxy() *Proxy {
	skipSSLEnvValue := os.Getenv("SKIP_SSL_VALIDATION")
	if len(skipSSLEnvValue) == 0 {
		skipSSLEnvValue = "false"
	}
	skipSSL, _ := strconv.ParseBool(skipSSLEnvValue)

	targetURL := os.Getenv("PROXY_TARGET_URL")
	if len(targetURL) == 0 {
		targetURL = "http://capi.cf-system.svc.cluster.local"
	}

	return &Proxy{
		SkipSSLValidation: skipSSL,
		ProxyTargetURL:    targetURL,
	}
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.ReverseProxy(rw, req)
}

func (p *Proxy) ReverseProxy(rw http.ResponseWriter, req *http.Request) {
	log.Printf("proxying request: [%s; %s; %s; %s; %s]\n", req.RemoteAddr, req.Host, req.Method, req.RequestURI, req.UserAgent())
	req.Header.Set("X-IP-Proxy-Demo", "X-IP-Proxy-Demo")

	target, err := url.Parse(p.ProxyTargetURL)
	if err != nil {
		log.Println(err.Error())
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Bad Proxy Target URL: " + err.Error()))
		return
	}

	// setup a reverse proxy and forward the original request to the target
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.SkipSSLValidation},
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host

	proxy.ServeHTTP(rw, req)
}
