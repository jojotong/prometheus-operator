// Copyright 2021 The prometheus-operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"fmt"
)

func (hc *HTTPConfig) Validate() error {
	if hc == nil {
		return nil
	}

	if (hc.BasicAuth != nil || hc.OAuth2 != nil) && (hc.BearerTokenSecret != nil) {
		return fmt.Errorf("at most one of basicAuth, oauth2, bearerTokenSecret must be configured")
	}

	if hc.Authorization != nil {
		if hc.BearerTokenSecret != nil {
			return fmt.Errorf("authorization is not compatible with bearerTokenSecret")
		}

		if hc.BasicAuth != nil || hc.OAuth2 != nil {
			return fmt.Errorf("at most one of basicAuth, oauth2 & authorization must be configured")
		}

		if err := hc.Authorization.Validate(); err != nil {
			return err
		}
	}

	if hc.OAuth2 != nil {
		if hc.BasicAuth != nil {
			return fmt.Errorf("at most one of basicAuth, oauth2 & authorization must be configured")
		}

		if err := hc.OAuth2.Validate(); err != nil {
			return err
		}
	}

	if hc.TLSConfig != nil {
		if err := hc.TLSConfig.Validate(); err != nil {
			return err
		}
	}

	return nil
}
