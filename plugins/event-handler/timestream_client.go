/*
Copyright 2015-2022 Gravitational, Inc.

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

import (
	"context"
	"fmt"
	"strconv"

	tlib "github.com/gravitational/teleport/plugins/lib"
	"github.com/gravitational/trace"

	"github.com/aws/aws-sdk-go/aws"
	awsSession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/timestreamwrite"
	log "github.com/sirupsen/logrus"
)

// TimestreamClient represents Timestream client
type TimestreamClient struct {
	// config is the timestream configuration
	config *TimestreamConfig
	// serverName is the name of the server
	// TODO: we want for this to be the account id from SC
	serverName string
	// client timestream client to sent requests
	client *timestreamwrite.TimestreamWrite
}

// NewTimestreamClient creates new TimestreamClient
func NewTimestreamClient(config *TimestreamConfig, serverName string) (*TimestreamClient, error) {
	opts := awsSession.Options{
		Config: aws.Config{
			Region:                        aws.String(config.TimestreamAwsRegion),
			CredentialsChainVerboseErrors: aws.Bool(true),
		},
	}
	// if the aws profile was set, set it in the aws session options
	if config.TimestreamAwsProfile != "" {
		opts.Profile = config.TimestreamAwsProfile
		opts.SharedConfigState = awsSession.SharedConfigEnable
	}
	session, err := awsSession.NewSessionWithOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	client := timestreamwrite.New(session)

	// check that timestream database and table exists
	_, err = client.DescribeTable(&timestreamwrite.DescribeTableInput{
		DatabaseName: aws.String(config.TimestreamDatabase),
		TableName:    aws.String(config.TimestreamDatabase),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &TimestreamClient{
		config:     config,
		serverName: serverName,
		client:     client,
	}, nil
}

// Send sends event to timestream
func (t *TimestreamClient) Send(ctx context.Context, streamName string, e *TeleportEvent) error {
	log.WithField("event", fmt.Sprintf("%+v", e)).Debug("Event to send")

	if e.User == "" {
		log.Debug("Ignoring event as it has no user")
		return nil
	}

	// TODO: write batches of records with common attributes
	// https://docs.aws.amazon.com/timestream/latest/developerguide/code-samples.write.html#code-samples.write.write-batches-common-attrs
	output, err := t.client.WriteRecords(&timestreamwrite.WriteRecordsInput{
		DatabaseName: aws.String(t.config.TimestreamDatabase),
		TableName:    aws.String(t.config.TimestreamDatabase),
		Records: []*timestreamwrite.Record{
			{
				Dimensions: []*timestreamwrite.Dimension{
					{
						Name:  aws.String("server_name"),
						Value: aws.String(t.serverName),
					},
					{
						Name:  aws.String("event_type"),
						Value: aws.String(e.Type),
					},
				},
				// TODO: unclear whether user should be a measure or a dimension
				MeasureName:      aws.String("user"),
				MeasureValue:     aws.String(e.User),
				MeasureValueType: aws.String("STRING"),
				Time:             aws.String(strconv.FormatInt(e.Time.Unix(), 10)),
				TimeUnit:         aws.String("SECONDS"),
			},
		},
	})
	if err != nil {
		// err returned by client.WriteRecords() would never have status canceled
		if tlib.IsCanceled(ctx.Err()) {
			return trace.Wrap(ctx.Err())
		}

		return trace.Wrap(err)
	}

	log.WithField("total ingested", *output.RecordsIngested.Total).WithField("memory store ingested", *output.RecordsIngested.MemoryStore).Debug("Event pushed to timestream")
	return nil
}
