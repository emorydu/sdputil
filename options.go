// Copyright 2023 Emory.Du <orangeduxiaocheng@gmail.com>. All rights reserved.
// Use of this source code is governed by a Apache2.0 style
// license that can be found in the LICENSE file.

package sdputil

import (
	"encoding/json"
	"os"
)

// Options defines configuration items related to builder.
type Options struct {
	Path string `json:"path" mapstructure:"path"`
}

// NewOptions create an Options object with default parameters.
func NewOptions() *Options {
	return &Options{
		Path: "/dev/authon_netfilter",
	}
}

func (o *Options) String() string {
	data, _ := json.Marshal(o)

	return string(data)
}

func (o *Options) Fd() (*os.File, uintptr, error) {
	f, err := os.Open(o.Path)
	if err != nil {
		return nil, 0, err
	}

	return f, f.Fd(), nil
}
