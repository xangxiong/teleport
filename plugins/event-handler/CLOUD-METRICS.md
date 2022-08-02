### Pushing Teleport events to Timestream

```bash
cd teleport/plugins/event-handler/
```

```bash
tsh login --proxy=vitor09.teleport.sh --user=vitor@goteleport.com
```

Create role and user:
```bash
echo "kind: role
metadata:
  name: teleport-event-handler
spec:
  allow:
    rules:
      - resources: ['event']
        verbs: ['list','read']
version: v5" | tctl create

echo "kind: user
metadata:
  name: teleport-event-handler
spec:
  roles: ['teleport-event-handler']
version: v2" | tctl create
```

If needed, these can be removed with:
```bash
tctl rm user/teleport-event-handler
tctl rm role/teleport-event-handler
```

```bash
tctl auth sign --out identity --user teleport-event-handler    
```

```bash
# assume the role 'cloudteam-dev-role`
export AWS_PROFILE=cloudteam-dev-role
aws sso login --profile tc-dev

# confirm that the role 'cloudteam-dev-role` was assumed
aws sts get-caller-identity | jq '.Arn'
```

Go to AWS and create Timestream database named `cloud-metrics-db` with an `events` table.

```
echo '
storage = "./storage"
timeout = "10s"
batch = 20
namespace = "default"

[forward.timestream]
database = "cloud-metrics-db"
table = "events"
aws-region = "us-west-2"
aws-profile = "cloudteam-dev-role"

[teleport]
addr = "vitor09.teleport.sh:443"
identity = "identity"
' > event-handler-config.toml

rm -rf storage && make build && ./build/teleport-event-handler start --config event-handler-config.toml --start-time 2021-01-01T00:00:00Z
```