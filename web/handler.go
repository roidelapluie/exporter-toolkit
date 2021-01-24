// Copyright 2020 The Prometheus Authors
// This code is partly borrowed from Caddy:
//    Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-kit/kit/log"
	"golang.org/x/crypto/bcrypt"
)

func validateUsers(configPath string) error {
	c, err := getConfig(configPath)
	if err != nil {
		return err
	}

	for _, p := range c.Users {
		_, err = bcrypt.Cost([]byte(p))
		if err != nil {
			return err
		}
	}

	return nil
}

// headerConfig represents an HTTP headers configuration.
type headerConfig struct {
	XFrameOptions           string `yaml:"X-Frame-Options,omitempty"`
	XContentTypeOptions     string `yaml:"X-Content-Type-Options,omitempty"`
	XXSSProtection          string `yaml:"X-XSS-Protection"`
	StrictTransportSecurity string `yaml:"Strict-Transport-Security,omitempty"`
}

// Validate that the provided configuration is correct.
// It does not check the validity of all the values, only the ones which are
// well-defined enumerations.
func (c *headerConfig) Validate() error {
	if c.XFrameOptions != "" && c.XFrameOptions != "deny" && c.XFrameOptions != "sameorigin" {
		return fmt.Errorf("invalid value for X-Frame-Options. Expected one of: [ deny, sameorigin ], but got: %s", c.XFrameOptions)
	}
	if c.XContentTypeOptions != "" && c.XContentTypeOptions != "nosniff" {
		return fmt.Errorf("invalid value for X-Content-Type-Options. Expected nosniff, but got: %s", c.XContentTypeOptions)
	}
	return nil
}

func (c *headerConfig) setHeader(header http.Header) {
	if c.XFrameOptions != "" {
		header.Set("X-Frame-Options", c.XFrameOptions)
	}
	if c.XContentTypeOptions != "" {
		header.Set("X-Content-Type-Options", c.XContentTypeOptions)
	}
	if c.XXSSProtection != "" {
		header.Set("X-XSS-Protection", c.XXSSProtection)
	}
	if c.StrictTransportSecurity != "" {
		header.Set("Strict-Transport-Security", c.StrictTransportSecurity)
	}
}

type webHandler struct {
	tlsConfigPath string
	handler       http.Handler
	logger        log.Logger
	cache         *cache
	// bcryptMtx is there to ensure that bcrypt.CompareHashAndPassword is run
	// only once in parallel as this is CPU intensive.
	bcryptMtx sync.Mutex
}

func (u *webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := getConfig(u.tlsConfigPath)
	if err != nil {
		u.logger.Log("msg", "Unable to parse configuration", "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Configure http headers.
	c.HTTPConfig.Header.setHeader(w.Header())

	if len(c.Users) == 0 {
		u.handler.ServeHTTP(w, r)
		return
	}

	user, pass, auth := r.BasicAuth()
	if auth {
		hashedPassword, validUser := c.Users[user]

		if !validUser {
			// The user is not found. Use a fixed password hash to
			// prevent user enumeration by timing requests.
			// This is a bcrypt-hashed version of "fakepassword".
			hashedPassword = "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi"
		}

		cacheKey := hex.EncodeToString(append(append([]byte(user), []byte(hashedPassword)...), []byte(pass)...))
		authOk, ok := u.cache.get(cacheKey)

		if !ok {
			// This user, hashedPassword, password is not cached.
			u.bcryptMtx.Lock()
			err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(pass))
			u.bcryptMtx.Unlock()

			authOk = err == nil
			u.cache.set(cacheKey, authOk)
		}

		if authOk && validUser {
			u.handler.ServeHTTP(w, r)
			return
		}
	}

	w.Header().Set("WWW-Authenticate", "Basic")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
