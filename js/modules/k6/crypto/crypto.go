/*
 *
 * k6 - a next-generation load testing tool
 * Copyright (C) 2017 Load Impact
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"

	"github.com/dop251/goja"

	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
)

type (
	// RootModule is the global module instance that will create module
	// instances for each VU.
	RootModule struct{}

	// Crypto represents an instance of the crypto module.
	Crypto struct {
		vu  modules.VU
		obj *goja.Object
	}
)

var (
	_ modules.Module   = &RootModule{}
	_ modules.Instance = &Crypto{}
)

// New returns a pointer to a new RootModule instance.
func New() *RootModule {
	return &RootModule{}
}

// NewModuleInstance implements the modules.Module interface to return
// a new instance for each VU.
func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	rt := vu.Runtime()
	o := rt.NewObject()
	mi := &Crypto{vu: vu, obj: o}

	mustExport := func(name string, value interface{}) {
		if err := mi.obj.Set(name, value); err != nil {
			common.Throw(rt, err)
		}
	}

	mustExport("createHash", mi.CreateHash)
	mustExport("createHMAC", mi.CreateHMAC)
	mustExport("hmac", mi.HMAC)
	mustExport("md4", mi.MD4)
	mustExport("md5", mi.MD5)
	mustExport("randomBytes", mi.RandomBytes)
	mustExport("ripemd160", mi.Ripemd160)
	mustExport("sha1", mi.SHA1)
	mustExport("sha256", mi.SHA256)
	mustExport("sha384", mi.SHA384)
	mustExport("sha512", mi.SHA512)
	mustExport("sha512_224", mi.SHA512224)
	mustExport("sha512_256", mi.SHA512256)
	mustExport("hexEncode", mi.HexEncode)

	return mi
}

// Exports returns the exports of the execution module.
func (c *Crypto) Exports() modules.Exports {
	return modules.Exports{Default: c.obj}
}

// RandomBytes returns random data of the given size.
func (c *Crypto) RandomBytes(size int) *goja.ArrayBuffer {
	rt := c.vu.Runtime()
	if size < 1 {
		common.Throw(rt, errors.New("invalid size"))
	}
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		common.Throw(rt, err)
	}
	ab := rt.NewArrayBuffer(bytes)
	return &ab
}

// MD4 returns the MD4 hash of input in the given encoding.
func (c *Crypto) MD4(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("md4")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// MD5 returns the MD5 hash of input in the given encoding.
func (c *Crypto) MD5(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("md5")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// SHA1 returns the SHA1 hash of input in the given encoding.
func (c *Crypto) SHA1(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("sha1")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// SHA256 returns the SHA256 hash of input in the given encoding.
func (c *Crypto) SHA256(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("sha256")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// SHA384 returns the SHA384 hash of input in the given encoding.
func (c *Crypto) SHA384(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("sha384")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// SHA512 returns the SHA512 hash of input in the given encoding.
func (c *Crypto) SHA512(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("sha512")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// SHA512224 returns the SHA512/224 hash of input in the given encoding.
func (c *Crypto) SHA512224(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("sha512_224")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// SHA512256 returns the SHA512/256 hash of input in the given encoding.
func (c *Crypto) SHA512256(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("sha512_256")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// Ripemd160 returns the RIPEMD160 hash of input in the given encoding.
func (c *Crypto) Ripemd160(input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHash("ripemd160")
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

// CreateHash returns a Hasher instance that uses the given algorithm.
func (c *Crypto) CreateHash(algorithm string) *Hasher {
	hashfn := c.parseHashFunc(algorithm)
	return &Hasher{
		runtime: c.vu.Runtime(),
		hash:    hashfn(),
	}
}

// HexEncode returns a string with the hex representation of the provided byte
// array or ArrayBuffer.
func (c *Crypto) HexEncode(data interface{}) string {
	d, err := common.ToBytes(data)
	if err != nil {
		common.Throw(c.vu.Runtime(), err)
	}
	return hex.EncodeToString(d)
}

// CreateHMAC returns a new HMAC hash using the given algorithm and key.
func (c *Crypto) CreateHMAC(algorithm string, key interface{}) *Hasher {
	h := c.parseHashFunc(algorithm)
	if h == nil {
		common.Throw(c.vu.Runtime(), fmt.Errorf("invalid algorithm: %s", algorithm))
	}

	kb, err := common.ToBytes(key)
	if err != nil {
		common.Throw(c.vu.Runtime(), err)
	}

	return &Hasher{runtime: c.vu.Runtime(), hash: hmac.New(h, kb)}
}

// HMAC returns a new HMAC hash of input using the given algorithm and key
// in the given encoding.
func (c *Crypto) HMAC(algorithm string, key, input interface{}, outputEncoding string) interface{} {
	hasher := c.CreateHMAC(algorithm, key)
	hasher.Update(input)
	return hasher.Digest(outputEncoding)
}

func (c *Crypto) parseHashFunc(a string) func() hash.Hash {
	var h func() hash.Hash
	switch a {
	case "md4":
		h = md4.New
	case "md5":
		h = md5.New
	case "sha1":
		h = sha1.New
	case "sha256":
		h = sha256.New
	case "sha384":
		h = sha512.New384
	case "sha512_224":
		h = sha512.New512_224
	case "sha512_256":
		h = sha512.New512_256
	case "sha512":
		h = sha512.New
	case "ripemd160":
		h = ripemd160.New
	}
	return h
}

// Hasher wraps an hash.Hash with goja.Runtime.
type Hasher struct {
	runtime *goja.Runtime
	hash    hash.Hash
}

// Update the hash with the input data.
func (hasher *Hasher) Update(input interface{}) {
	d, err := common.ToBytes(input)
	if err != nil {
		common.Throw(hasher.runtime, err)
	}
	_, err = hasher.hash.Write(d)
	if err != nil {
		common.Throw(hasher.runtime, err)
	}
}

// Digest returns the hash value in the given encoding.
func (hasher *Hasher) Digest(outputEncoding string) interface{} {
	sum := hasher.hash.Sum(nil)

	switch outputEncoding {
	case "base64":
		return base64.StdEncoding.EncodeToString(sum)

	case "base64url":
		return base64.URLEncoding.EncodeToString(sum)

	case "base64rawurl":
		return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum)

	case "hex":
		return hex.EncodeToString(sum)

	case "binary":
		ab := hasher.runtime.NewArrayBuffer(sum)
		return &ab

	default:
		err := errors.New("Invalid output encoding: " + outputEncoding)
		common.Throw(hasher.runtime, err)
	}

	return ""
}
