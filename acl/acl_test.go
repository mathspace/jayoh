package acl

import (
	"strings"
	"testing"
)

const (
	aclistStr = `
{
  "users": {
    "jim": {
      "groups": ["a", "b", "c"],
      "passwords": [
        "$2y$05$Tj1LgEgIqfsgyziIocQbyeFscaKv8HfsJwZ6XndnPDiTFzH77IaQ.",
        "$2y$05$TMmgtNYWFWSf8W5ave1q6.pP2qK8WCDS6NJWBqpWVj.Jt4iGtMOH2"
      ],
      "keys": [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCv7SY7afyoCTInLoTGGlZtHmb1EguT9ZMUAjjcKDZOT0wTR30hcjt9D1NvzYPrMK4Lo+eksTx85awwCY78Nxc20UnsBCKB7LEUcfG46W8N2XvF8yi48FbEccNRPHsVenGy9mUcM4ZZX+2mQm69iqjdXOjLxzesiahJcBHaLVVnOYC/WyleNvKL/H3PP0TPOVIJHWBwBUHrDps1Z1ODzvUP7t/LRde/lE/thfUScBjznuraGLhEGdhNkVkqQYLox0OBODukRywsQxtz7eP9cCgbH0NNAs2vaFmtkCYuHdFzuT0gbBIugSkm123nK4BOuftGWhvLaBOe7t8+NIeLtF5x",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjsLA6AWjVDkJoMf45vmgh7kWv5hL6bLyBIdPQXD4tNgEF4JMg9P8ZK/p8wP00+BG/TTomj17W84bAWa2oxP/V44omLrBXOQesyx2SClTye9yIpdLWLHG9Eo9texjJdfDTInEXqsAfOusVZVktrTN1PDZNrMpyE92dCwz9BRUHt862rloZu1bK3ZgfashpTEfbww/nCncBR+0g5g7KZLVl+nWJs8bq/VoRhJYhciniCnWVVJUoPWAJwWqPNU9hKnm8bZmep2y/gfIRXuRgPf3cvS/CpkPDqYg9o03kzwvy8MFJOYxhFyEeTTMU1KYMqAKCLUA3MVIT2jHkyCjxGouT"
      ]
    }
  },
  "rules": {
    "x": {
      "groups": ["a", "b"],
      "host_patterns": ["10.0.0.0/24", "a.example.com", "30.20.10.10/32", "9.8.7.5"]
    },
    "y": {
      "groups": ["d"],
      "host_patterns": ["20.0.0.0/24", "d.example.com", "20.10.10.10/32", "1.2.3.4"]
    }
  }
}
`
)

var (
	aclist = &ACL{}
	pass1  = []byte("123456")
	pass2  = []byte("abcdef")
)

func init() {
	if err := aclist.Load(strings.NewReader(aclistStr)); err != nil {
		panic(err)
	}
}

func TestIsValidPasswordIncorrect(t *testing.T) {
	if aclist.IsValidPassword("jim", []byte("badpassword")) {
		t.Fail()
	}
}
func TestIsValidPasswordCorrect(t *testing.T) {
	if !aclist.IsValidPassword("jim", pass1) {
		t.Fail()
	}
}
func TestIsValidPasswordCorrect2(t *testing.T) {
	if !aclist.IsValidPassword("jim", pass2) {
		t.Fail()
	}
}
func TestIsValidPasswordCrossUser(t *testing.T) {
	if aclist.IsValidPassword("mike", pass1) {
		t.Fail()
	}
}
func TestIsValidPasswordCrossUser2(t *testing.T) {
	if aclist.IsValidPassword("mike", pass1) {
		t.Fail()
	}
}
func TestIsValidPasswordBlank(t *testing.T) {
	if aclist.IsValidPassword("jim", []byte("")) {
		t.Fail()
	}
}
func TestIsValidPasswordNil(t *testing.T) {
	if aclist.IsValidPassword("jim", nil) {
		t.Fail()
	}
}
func TestIsValidPasswordBlankUser(t *testing.T) {
	if aclist.IsValidPassword("", nil) {
		t.Fail()
	}
}

func TestIsAllowedHostAccessCorrect(t *testing.T) {
	if !aclist.IsAllowedHostAccess("jim", "10.0.0.66") {
		t.Fail()
	}
}
func TestIsAllowedHostAccessCorrect2(t *testing.T) {
	if !aclist.IsAllowedHostAccess("jim", "30.20.10.10") {
		t.Fail()
	}
}
func TestIsAllowedHostAccessCorrect3(t *testing.T) {
	if !aclist.IsAllowedHostAccess("jim", "a.example.com") {
		t.Fail()
	}
}
func TestIsAllowedHostAccessIncorrect(t *testing.T) {
	if aclist.IsAllowedHostAccess("jim", "30.20.10.11") {
		t.Fail()
	}
}
func TestIsAllowedHostAccessIncorrect2(t *testing.T) {
	if aclist.IsAllowedHostAccess("jim", "example.com") {
		t.Fail()
	}
}
func TestIsAllowedHostAccessIncorrect3(t *testing.T) {
	if aclist.IsAllowedHostAccess("mike", "10.0.0.1") {
		t.Fail()
	}
}
