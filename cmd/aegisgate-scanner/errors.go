// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

// ErrInvalidLogFormat is returned when an unsupported log format is specified.
var ErrInvalidLogFormat = fmt.Errorf("invalid log format: must be 'text' or 'json'")
