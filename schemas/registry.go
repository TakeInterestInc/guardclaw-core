// SPDX-License-Identifier: Apache-2.0
package schemas

import _ "embed"

//go:embed guardclaw-pattern-ids.v1.json
var registry []byte

// PatternRegistry returns an independent copy of the fixed baseline registry.
func PatternRegistry() []byte { return append([]byte(nil), registry...) }
