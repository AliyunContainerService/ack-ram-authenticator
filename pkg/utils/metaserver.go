package utils

import (
	"io/ioutil"
	"net/http"
)

const (
	//MetadataURL is the ECS metadata server addr
	MetadataURL = "http://100.100.100.200/latest/meta-data/"
	RegionID    = "region-id"
	PrivateIPv4 = "private-ipv4"
)

//GetMetaData return host regionid, zoneid
func GetMetaData(resource string) string {
	resp, err := http.Get(MetadataURL + resource)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
