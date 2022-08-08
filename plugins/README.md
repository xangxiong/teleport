
### Streaming tests

```
echo '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' > assume-policy.json

aws iam create-role --role-name vitor-streaming-test-role --assume-role-policy-document file://assume-policy.json

echo '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "dynamodb:*",
        "timestream:*",
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}' > streaming-access.json

aws iam put-role-policy --role-name vitor-streaming-test-role --policy-name streaming-access --policy-document file://streaming-access.json
```

```
aws sts assume-role --role-arn $(aws iam get-role --role-name vitor-streaming-test-role | jq '.Role.Arn' | xargs) --role-session-name session-test > credentials.json

export AWS_ACCESS_KEY_ID=$(cat credentials.json | jq '.Credentials.AccessKeyId' | xargs)
export AWS_SECRET_ACCESS_KEY=$(cat credentials.json | jq '.Credentials.SecretAccessKey' | xargs)
export AWS_SESSION_TOKEN=$(cat credentials.json | jq '.Credentials.SessionToken' | xargs)
```

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
# ./shards writer prefix1:writes_per_second prefix2:writes_per_second ..

go build -o shards shards.go && chmod u+x shards
./shards writer a:100 b:200 c:300
```