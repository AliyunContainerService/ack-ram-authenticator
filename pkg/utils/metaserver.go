package utils

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"

	"time"
)

const (
	//MetadataURL is the ECS metadata server addr
	MetadataURL   = "http://100.100.100.200/latest/meta-data/"
	RegionID      = "region-id"
	PrivateIPv4   = "private-ipv4"
	ClientTimeout = time.Second //only 1s timeout for non ECS client
)

//GetMetaData return host regionid, zoneid
func GetMetaData(resource string) string {
	var resp []byte
	sc, err := requestWithHeader("GET", MetadataURL+resource, nil, nil, resp, ClientTimeout)
	if err != nil || sc != http.StatusOK {
		return ""
	}

	return string(resp)
}

// request http restful api
func requestWithHeader(method, urlStr string, data interface{}, header http.Header, result []byte, timeout time.Duration) (int, error) {
	var bodyData []byte
	if data != nil {
		var err error
		bodyData, err = json.Marshal(data)
		log.Infof("http_request_params = %s, data = %s", urlStr, string(bodyData))
		if err != nil {
			log.Warnf("Request:json.Marshal encounter error %v, data:%++v", err, data)
			return 0, err
		}
	}
	client := &http.Client{}
	if timeout != 0 {
		client.Timeout = timeout
	}

	req, err := http.NewRequest(method, urlStr, strings.NewReader(string(bodyData)))
	if err != nil {
		log.Warnf("Request:http.NewRequest encounter error %v", err)
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json")

	if header != nil {
		req.Header = header
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		log.Warnf("Request:client.Do encounter error %v", err)
		return 0, err
	}
	defer func() {
		resp.Body.Close()
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}()
	result, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf(" ioutil.ReadAll error ++%v", err)
		return resp.StatusCode, err
	}
	cost := (float32)(time.Since(start).Nanoseconds()) / (float32)(1000000)
	log.Warnf("http_response url = %s, cost = %f ms, code =  %d", urlStr, cost, resp.StatusCode)
	return resp.StatusCode, nil
}
