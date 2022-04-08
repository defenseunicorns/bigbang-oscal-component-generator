package http

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

func FetchFromHTTPResource(uri *url.URL) ([]byte, error) {
	c := http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(uri.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response body %v", err)
	}
	return body, nil
}
