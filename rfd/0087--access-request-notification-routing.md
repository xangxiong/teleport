---
authors: Hugo Hervieux (hugo.hervieux@goteleport.com)
state: draft
---
# RFD 87 - Access request notification routing

## What

Provide a granular way for administrators to configure which access-requests notifications should be delivered to whom over which medium.

## Why

- Teleport access request routing is not configured the same way depending on the plugin: Pagerduty uses annotations while most plugins use a role_to_recipient map in the plugin config. Users leveraging both PagerDuty and Slack plugins have to deal with two configuration languages.
- Current Pagerduty request routing applies the same rule to all requests from the same role, regardless of the requested role. All access requests don't have the same severity, users wanting to route access requests differently have to create multiple roles. Depending on the company size and structure cardinality can become a problem. See https://github.com/gravitational/teleport-plugins/issues/597
- Access request routing map baked in the plugin deployment:
  - Will become huge for big orgs
  - Requires redeploying each time a change is done
  - Do not allow to route requests regarding of who requests

## Details

### User story

Bob is a developer. He deploys code using CI/CD pipelines. He can request access to prod in read-only mode and dev in read-write mode for debugging. In case of incident he can request prod read-write access.
Alice is the lead-dev, she grants regular access requests through MsTeams during open hours and can also approve urgent read-write requests.
Alice should not be paged each time Bob needs to debug something during open hours, but in case of incident Bob needs immediate access and Alice should be paged.

In Teleport terms:

- the role `developer` can request roles `dev-rw`, `prod-ro` and `prod-rw`
- the role `lead-developer` can accept requests
- only `prod-rw` access requests should trigger a PagerDuty incident
- `dev-rw` and `prod-ro` access requests should trigger a MsTeams message

### Suggestion 1: With a where clause

```
kind: role
metadata:
  name: developer
spec:
  allow:
    request:
      roles: ["dev-ro", "prod-ro","prod-rw"]
      destinations:
      - where: "role eq prod-ro"
        plugin: pagerduty
        target: ["Teleport Alice"]
      - where: "role neq prod-rw"
        plugin: msteams
        target: ["Alice@example.com"]
```

`where` is a where clause it can be evaluated server-side or client-side
`plugin` acts as a label and each plugin instance can filter based on this

The destinations are additive:
- they can come from the role_to_recipient map
- they can come from the destinations on the role
- they can be added in the requests additional recpipients
- they can come from annotations (backward compatibility for pagerduty plugin)

### Suggestion 2: With the existing annotation system

```
kind: role
metadata:
 name: developer
spec:
 allow:
  request:
   roles: ["prod-ro","prod-rw"]
   annotations:
    pagerduty_services: ["Teleport Alice"]
    pagerduty_allow_roles: "prod-rw"
    msteams_services: ["alice@example.com"]
    msteams_deny_roles: "prod-rw"
```

Each plugin watches its own annotations:

*`_services` lists the destinations
*`_allow_roles`  allowlist
*`_deny_roles` blocklist
