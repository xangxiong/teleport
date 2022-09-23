/*
Copyright 2018 Gravitational, Inc.

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

package main

// const (
// 	// loginUsageFooter is printed at the bottom of `tsh help login` output
// 	loginUsageFooter = `NOTES:
//   The proxy address format is host:https_port,ssh_proxy_port

//   Passwordless only works in local auth
//   --auth=passwordless flag can be omitted if your cluster configuration set the connector_name: passwordless option.

// EXAMPLES:
//   Use ports 8080 and 8023 for https and SSH proxy:
//   $ tsh --proxy=host.example.com:8080,8023 login

//   Use port 8080 and 3023 (default) for SSH proxy:
//   $ tsh --proxy=host.example.com:8080 login

//   Login and select cluster "two":
//   $ tsh --proxy=host.example.com login two

//   Select cluster "two" using existing credentials and proxy:
//   $ tsh login two

//   For passwordless authentication use:
//   $ tsh login --auth=passwordless`

// 	// missingPrincipalsFooter is printed at the bottom of `tsh ls` when no results are returned.
// 	missingPrincipalsFooter = `
//   Not seeing nodes? Your user may be missing Linux principals. If trying teleport for the first time, follow this guide:

// https://goteleport.com/docs/getting-started/linux-server/#step-46-create-a-teleport-user-and-set-up-two-factor-authentication
//   `
// )
