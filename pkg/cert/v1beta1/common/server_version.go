/*
Copyright 2021 The Kubeflow Authors.

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

package common

import (
	"k8s.io/client-go/discovery"
	"strconv"
)

type ServerVersion struct {
	Major int
	Minor int
}

func (v *ServerVersion) NewServerVersion(discovery discovery.DiscoveryInterface) error {
	versions, err := discovery.ServerVersion()
	if err != nil {
		return err
	}
	v.Major, err = strconv.Atoi(versions.Major)
	if err != nil {
		return err
	}
	v.Minor, err = strconv.Atoi(versions.Minor)
	if err != nil {
		return err
	}
	return nil
}
