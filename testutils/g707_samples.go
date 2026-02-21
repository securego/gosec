package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG707 - SMTP command/header injection via taint analysis
var SampleCodeG707 = []CodeSample{
	{[]string{`
package main

import (
	"net/http"
	"net/smtp"
)

func handler(r *http.Request) {
	from := r.FormValue("from")
	to := []string{r.FormValue("to")}
	_ = smtp.SendMail("127.0.0.1:25", nil, from, to, []byte("Subject: Hi\r\n\r\nbody"))
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"net/smtp"
)

func handler(r *http.Request, c *smtp.Client) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	_ = c.Mail(from)
	_ = c.Rcpt(to)
}
`}, 2, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"net/mail"
	"net/smtp"
)

func handler(r *http.Request) {
	parsed, err := mail.ParseAddress(r.FormValue("from"))
	if err != nil {
		return
	}
	_ = smtp.SendMail("127.0.0.1:25", nil, parsed.Address, []string{"recipient@example.com"}, []byte("Subject: Hi\r\n\r\nbody"))
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"net/mail"
	"net/smtp"
)

func handler(r *http.Request) {
	addresses, err := mail.ParseAddressList(r.FormValue("to"))
	if err != nil {
		return
	}

	recipients := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		recipients = append(recipients, addr.Address)
	}

	_ = smtp.SendMail("127.0.0.1:25", nil, "sender@example.com", recipients, []byte("Subject: Hi\r\n\r\nbody"))
}
`}, 0, gosec.NewConfig()},
}
