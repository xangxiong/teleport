
### Streaming tests

- AWS login
```bash
rm ~/.aws/credentials

# assume the role 'cloudteam-dev-role`
export AWS_PROFILE=cloudteam-dev-role
aws sso login --profile tc-dev

# confirm that the role 'cloudteam-dev-role` was assumed
aws sts get-caller-identity | jq '.Arn'
```

- setup
```
go build -o shards shards.go && chmod u+x shards
./shards setup
```

- reader
```bash
go build -o shards shards.go && chmod u+x shards
./shards reader
```

- writer
```bash
# usage
# ./shards writer key1:writes_per_second key2:writes_per_second ..

go build -o shards shards.go && chmod u+x shards
./shards writer a:100 b:200 c:300
```