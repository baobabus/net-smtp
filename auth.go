// Copyright 2015 Aleksey Blinov. All rights reserved.

package net_smtp

import (
	"net/smtp"
	"fmt"
)

type loginAuth struct {
	username string
	password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, fmt.Errorf("unexpected server challenge: \"%s\"", fromServer)
		}
	}
	return nil, nil
}

type autoAuth struct {
	identity  string
	username  string
	password  string
	host      string
	backend   smtp.Auth
}

func AutoAuth(identity, username, password, host string) smtp.Auth {
	return &autoAuth{identity, username, password, host, nil}
}

func (this *autoAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	for _, mechanism := range server.Auth {
		switch mechanism {
		case "PLAIN":
			this.backend = smtp.PlainAuth(this.identity, this.username, this.password, this.host)
		case "LOGIN":
			this.backend = LoginAuth(this.username, this.password)
		case "CRAM-MD5":
			this.backend = smtp.CRAMMD5Auth(this.username, this.password)
		}
		if this.backend != nil { break; }
	}
	if this.backend == nil {
		return "", nil, fmt.Errorf("no suitable authentication for advertised mechanisms: \"%s\"", server.Auth)
	}
	return this.backend.Start(server)
}

func (this *autoAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if this.backend == nil {
		return nil, fmt.Errorf("no backend")
	}
	return this.backend.Next(fromServer, more)
}

