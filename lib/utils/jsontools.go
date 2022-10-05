/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"github.com/gravitational/trace"
	jsoniter "github.com/json-iterator/go"
)

// FastUnmarshal uses the json-iterator library for fast JSON unmarshalling.
// Note, this function marshals floats with 6 digits precision.
func FastUnmarshal(data []byte, v interface{}) error {
	iter := jsoniter.ConfigFastest.BorrowIterator(data)
	defer jsoniter.ConfigFastest.ReturnIterator(iter)

	iter.ReadVal(v)
	if iter.Error != nil {
		return trace.Wrap(iter.Error)
	}

	return nil
}

// SafeConfig uses jsoniter's ConfigFastest settings but enables map key
// sorting to ensure CompareAndSwap checks consistently succeed.
var SafeConfig = jsoniter.Config{
	EscapeHTML:                    false,
	MarshalFloatWith6Digits:       true, // will lose precision
	ObjectFieldMustBeSimpleString: true, // do not unescape object field
	SortMapKeys:                   true,
}.Froze()

// FastMarshal uses the json-iterator library for fast JSON marshalling.
// Note, this function unmarshals floats with 6 digits precision.
func FastMarshal(v interface{}) ([]byte, error) {
	data, err := SafeConfig.Marshal(v)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return data, nil
}
