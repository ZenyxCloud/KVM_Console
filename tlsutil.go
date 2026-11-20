package main

import "crypto/tls"

func insecureLocalTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}
