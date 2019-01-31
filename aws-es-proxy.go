package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	// log "github.com/Sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
)

type proxy struct {
	Endpoint      string
	ListenAddress string

	scheme  string
	host    string
	region  string
	service string
	signer  *v4.Signer
}

func (p *proxy) init() error {
	var link *url.URL
	var err error

	if link, err = url.Parse(p.Endpoint); err != nil {
		return fmt.Errorf("error: failure while parsing endpoint: %s. Error: %s",
			p.Endpoint, err.Error())
	}

	// Only http/https are supported schemes
	switch link.Scheme {
	case "http", "https":
	default:
		link.Scheme = "https"
	}

	// Unknown schemes sometimes result in empty host value
	if link.Host == "" {
		return fmt.Errorf("error: empty host or protocol information in submitted endpoint (%s)",
			p.Endpoint)
	}

	// AWS SignV4 enabled, extract required parts for signing process
	// Extract region and service from link
	parts := strings.Split(link.Host, ".")

	if len(parts) == 5 {
		p.region, p.service = parts[1], parts[2]
	} else {
		return fmt.Errorf("error: submitted endpoint is not a valid Amazon ElasticSearch Endpoint")
	}

	// Update proxy struct
	p.scheme = link.Scheme
	p.host = link.Host

	// get AWS signer - it wil auto refresh it's own creds
	sess, err := session.NewSession()
	if err != nil {
		return err
	}
	p.signer = v4.NewSigner(sess.Config.Credentials)

	return nil
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqBodyContent, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("err1")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ep := *r.URL
	ep.Host = p.host
	ep.Scheme = p.scheme

	req, err := http.NewRequest(r.Method, ep.String(), bytes.NewReader(reqBodyContent))
	if err != nil {
		log.Println("err2")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Recent versions of ES/Kibana require
	// "kbn-version" and "content-type: application/json"
	// headers to exist in the request.
	// If missing requests fails.
	if val, ok := r.Header["Kbn-Version"]; ok {
		req.Header.Set("Kbn-Version", val[0])
	}
	if val, ok := r.Header["Content-Type"]; ok {
		req.Header.Set("Content-Type", val[0])
	}

	// Sign the request with AWSv4
	_, err = p.signer.Sign(req, bytes.NewReader(reqBodyContent), p.service, p.region, time.Now())
	if err != nil {
		log.Println("err3")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	xx, err := httputil.DumpRequest(req, true)
	log.Printf("%s\n%s", xx, err)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("err4")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	// Write back headers to requesting client
	rh := w.Header()
	for k, vals := range resp.Header {
		for _, v := range vals {
			rh.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Send response back to requesting client
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println(err) // can't do http.Error as status code is already written
	}
}

func (p *proxy) RunForever() error {
	err := p.init()
	if err != nil {
		return err
	}

	log.Printf("Listening on %s...\n", p.ListenAddress)
	server := &http.Server{
		Addr:    p.ListenAddress,
		Handler: p,
	}

	// Shutdown on signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sc
		log.Println("Signal received, shutting down...")
		ctx, cx := context.WithTimeout(context.Background(), 20*time.Second)
		defer cx()
		err := server.Shutdown(ctx)
		if err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	}()

	return server.ListenAndServe()
}

func main() {
	p := &proxy{}

	flag.StringVar(&p.Endpoint, "endpoint", "", "Amazon ElasticSearch Endpoint (e.g: https://dummy-host.eu-west-1.es.amazonaws.com)")
	flag.StringVar(&p.ListenAddress, "listen", "127.0.0.1:9200", "Local TCP port to listen on")
	flag.Parse()

	if p.Endpoint == "" {
		log.Println("You need to specify Amazon ElasticSearch endpoint.")
		log.Fatalln("Please run with '-h' for a list of available arguments.")
	}

	err := p.RunForever()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalln(err)
	}
}
