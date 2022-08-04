/*
Copyright 2015-2020 Gravitational, Inc.

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
	"flag"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodbstreams"
	log "github.com/sirupsen/logrus"
)

const (
	AwsRegion               = endpoints.UsWest2RegionID
	AwsProfile              = "cloudteam-dev-role"
	TableName               = "test-stream-shards-iter-vitor"
	HighResPollingPeriod    = 10 * time.Second
	DefaultPollStreamPeriod = time.Second

	// hashKeyKey is a name of the hash key
	hashKeyKey  = "HashKey"
	channelSize = 1024 * 1024
)

type backend struct {
	Log              *log.Entry
	Dynamo           dynamodb.DynamoDB
	Streams          dynamodbstreams.DynamoDBStreams
	TableName        string
	RetryPeriod      time.Duration
	PollStreamPeriod time.Duration
}

type record struct {
	HashKey string
	Value   []byte
}

type shardEvent struct {
	records []*dynamodbstreams.Record
	shardID string
	err     error
}

type writerConfig struct {
	key             string
	writesPerSecond int64
}

func main() {
	// parse arguments
	debug := false
	flag.BoolVar(&debug, "debug", false, "Debug logging")
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatalf("Missing one of the following arguments: setup, reader, writers")
	}
	component := flag.Arg(0)

	ctx := context.Background()
	b, err := newBackend(ctx, component, debug)
	if err != nil {
		log.Fatal(trace.DebugReport(err))
	}

	switch component {
	case "setup":
		if err := b.setup(ctx); err != nil {
			log.Fatal(trace.DebugReport(err))
		}
	case "reader":
		if err := b.reader(ctx); err != nil {
			log.Fatal(trace.DebugReport(err))
		}
	case "writers":
		configs := make([]writerConfig, 0)
		for i := 1; i < len(flag.Args()); i++ {
			parts := strings.Split(flag.Arg(i), ":")
			if len(parts) != 2 {
				log.Fatalf("Invalid writers argument: %s", flag.Arg(i))
			}

			key := parts[0]
			writesPerSecond, err := strconv.Atoi(parts[1])
			if err != nil {
				log.Fatalf("Invalid writers argument: %s; %s", flag.Arg(i), err)
			}
			config := writerConfig{
				key:             key,
				writesPerSecond: int64(writesPerSecond),
			}
			configs = append(configs, config)
		}

		if len(configs) == 0 {
			log.Fatalf("Missing writers configuration")
		}

		var wg sync.WaitGroup
		for i := range configs {
			config := configs[i]
			wg.Add(1)

			go func() {
				defer wg.Done()
				if err := b.writer(ctx, config); err != nil {
					log.Fatal(trace.DebugReport(err))
				}
			}()
		}

		wg.Wait()
	default:
		log.Fatalf("Unexpected argument: %s", component)
	}
}

func newBackend(ctx context.Context, component string, debug bool) (*backend, error) {
	// aws session
	opts := session.Options{
		Config: aws.Config{
			Region:                        aws.String(AwsRegion),
			CredentialsChainVerboseErrors: aws.Bool(true),
		},
		Profile:           AwsProfile,
		SharedConfigState: session.SharedConfigEnable,
	}
	session, err := session.NewSessionWithOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	l := log.WithFields(log.Fields{trace.Component: component})
	if debug {
		l.Logger.SetLevel(log.DebugLevel)
	}
	return &backend{
		Log:              l,
		Dynamo:           *dynamodb.New(session),
		Streams:          *dynamodbstreams.New(session),
		TableName:        TableName,
		RetryPeriod:      HighResPollingPeriod,
		PollStreamPeriod: DefaultPollStreamPeriod,
	}, nil
}

func (b *backend) setup(ctx context.Context) error {
	// create table (with dynamoDB streams enabled) if it does not exist
	exists, err := b.tableExists(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	if exists {
		b.Log.Infof("Table %s already exists.", b.TableName)
	} else {
		err = b.createTable(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (b *backend) reader(ctx context.Context) error {
	streamArn, err := b.findStream(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	b.Log.Debugf("Found latest event stream %v.", aws.StringValue(streamArn))

	recordC := make(chan *dynamodbstreams.Record, channelSize)

	go func() {
		if err := b.asyncPollStreams(ctx, *streamArn, recordC); err != nil {
			b.Log.Errorf("Stream polling loop exited: %v", err)
		}
	}()

	for {
		select {
		case record := <-recordC:
			b.Log.Debug("%+v", record)
		case <-ctx.Done():
			b.Log.Debugf("Closed, returning reader loop.")
			return nil
		}
	}
}

func (b *backend) writer(ctx context.Context, config writerConfig) error {
	interval := time.Duration(int64(time.Second) / config.writesPerSecond)
	b.Log.Infof("Starting writer on key %s at %d writes per second (1 write every %s)", config.key, config.writesPerSecond, interval)

	ticker := time.NewTicker(interval)
	index := 0
	for {
		select {
		case t := <-ticker.C:
			b.Log.Debugf("Writing %d to key %s at %s", index, config.key, t)
			err := b.putRecord(ctx, config.key, index)
			if err != nil {
				return trace.Wrap(err)
			}
		case <-ctx.Done():
			b.Log.Debugf("Closed, returning from writer loop.")
			return nil
		}
	}
}

func (b *backend) putRecord(ctx context.Context, key string, value int) error {
	r := record{
		HashKey: key,
		Value:   []byte(strconv.Itoa(value)),
	}
	av, err := dynamodbattribute.MarshalMap(r)
	if err != nil {
		return trace.Wrap(err)
	}
	input := dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(b.TableName),
	}
	_, err = b.Dynamo.PutItemWithContext(ctx, &input)
	return trace.Wrap(err)
}

func (b *backend) asyncPollStreams(ctx context.Context, streamArn string, recordC chan *dynamodbstreams.Record) error {
	retry, err := utils.NewLinear(utils.LinearConfig{
		Step: b.RetryPeriod / 10,
		Max:  b.RetryPeriod,
	})
	if err != nil {
		b.Log.Errorf("Bad retry parameters: %v", err)
		return trace.Wrap(err)
	}

	for {
		err := b.pollStreams(ctx, streamArn, recordC)
		if err != nil {
			b.Log.Errorf("Poll streams returned with error: %v.", err)
		}
		b.Log.Debugf("Reloading %v.", retry)
		select {
		case <-retry.After():
			retry.Inc()
		case <-ctx.Done():
			b.Log.Debugf("Closed, returning from asyncPollStreams loop.")
			return nil
		}
	}
}

func (b *backend) pollStreams(externalCtx context.Context, streamArn string, recordC chan *dynamodbstreams.Record) error {
	ctx, cancel := context.WithCancel(externalCtx)
	defer cancel()

	set := make(map[string]struct{})
	eventsC := make(chan shardEvent)

	shouldStartPoll := func(shard *dynamodbstreams.Shard) bool {
		shardId := aws.StringValue(shard.ShardId)
		parentShardId := aws.StringValue(shard.ParentShardId)
		if _, ok := set[shardId]; ok {
			// already being polled
			return false
		}
		if _, ok := set[parentShardId]; ok {
			b.Log.Debugf("Skipping child shard: %s, still polling parent %s", shardId, parentShardId)
			// still processing parent
			return false

		}
		return true
	}

	refreshShards := func(init bool) error {
		shards, err := b.collectActiveShards(ctx, streamArn)
		if err != nil {
			return trace.Wrap(err)
		}

		var initC chan error
		if init {
			// first call to  refreshShards requires us to block on shard iterator
			// registration.
			initC = make(chan error, len(shards))
		}

		started := 0
		for i := range shards {
			if !shouldStartPoll(shards[i]) {
				continue
			}
			shardID := aws.StringValue(shards[i].ShardId)
			b.Log.Debugf("Adding active shard %v.", shardID)
			set[shardID] = struct{}{}
			go b.asyncPollShard(ctx, streamArn, shards[i], eventsC, initC)
			started++
		}

		// Q: I don't understand why we block on "shard iterator registration" only when starting up.
		// If we have to "block", shouldn't we block every time we start polling a new shard?
		if init {
			// block on shard iterator registration.
			for i := 0; i < started; i++ {
				select {
				case err = <-initC:
					if err != nil {
						return trace.Wrap(err)
					}
				case <-ctx.Done():
					return trace.Wrap(ctx.Err())
				}
			}
		}

		return nil
	}

	if err := refreshShards(true); err != nil {
		return trace.Wrap(err)
	}

	ticker := time.NewTicker(b.PollStreamPeriod)
	defer ticker.Stop()

	for {
		select {
		case event := <-eventsC:
			if event.err != nil {
				if event.shardID == "" {
					// empty shard IDs in err-variant events are programming bugs and will lead to
					// invalid state.
					// FIX: err -> event.err
					b.Log.WithError(event.err).Warnf("Forcing watch system reset due to empty shard ID on error (this is a bug)")
					return trace.BadParameter("empty shard ID")
				}
				delete(set, event.shardID)
				if event.err != io.EOF {
					b.Log.Debugf("Shard ID %v closed with error: %v, reseting buffers.", event.shardID, event.err)
					return trace.Wrap(event.err)
				}
				b.Log.Debugf("Shard ID %v exited gracefully.", event.shardID)
			} else {
				// Q: It seems that there's no checkpointing when streaming changes to the backend.
				for i := range event.records {
					select {
					case recordC <- event.records[i]:
					case <-ctx.Done():
						b.Log.Debugf("Context is closing, returning")
						return nil
					}
				}
			}
		case <-ticker.C:
			if err := refreshShards(false); err != nil {
				return trace.Wrap(err)
			}
		case <-ctx.Done():
			b.Log.Debugf("Context is closing, returning.")
			return nil
		}
	}
}

func (b *backend) findStream(ctx context.Context) (*string, error) {
	status, err := b.Dynamo.DescribeTableWithContext(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(b.TableName),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if status.Table.LatestStreamArn == nil {
		return nil, trace.NotFound("No streams found for table %v", b.TableName)
	}
	return status.Table.LatestStreamArn, nil
}

func (b *backend) pollShard(ctx context.Context, streamArn string, shard *dynamodbstreams.Shard, eventsC chan shardEvent, initC chan<- error) error {
	shardIterator, err := b.Streams.GetShardIteratorWithContext(ctx, &dynamodbstreams.GetShardIteratorInput{
		ShardId: shard.ShardId,
		// Q: Besides no checkpointing, the shard iterator type is set to LATEST, meaning that there's no worry about retrieving all events.
		// With checkpointing, we would know the last event retrieved from each (known) shard, and could set the shard iterator type to AFTER_SEQUENCE_NUMBER.
		// If the shard is unknown (i.e. no checkpointing info about it), we should probably set the shard iterator type to TRIM_HORIZON, which can retrieve events up-to 24h old.
		ShardIteratorType: aws.String(dynamodbstreams.ShardIteratorTypeLatest),
		StreamArn:         aws.String(streamArn),
	})

	if initC != nil {
		select {
		case initC <- err:
		case <-ctx.Done():
			return trace.ConnectionProblem(ctx.Err(), "context is closing")
		}
	}
	if err != nil {
		return trace.Wrap(err)
	}

	ticker := time.NewTicker(b.PollStreamPeriod)
	defer ticker.Stop()
	iterator := shardIterator.ShardIterator
	shardID := aws.StringValue(shard.ShardId)
	for {
		select {
		case <-ctx.Done():
			return trace.ConnectionProblem(ctx.Err(), "context is closing")
		case <-ticker.C:
			out, err := b.Streams.GetRecordsWithContext(ctx, &dynamodbstreams.GetRecordsInput{
				ShardIterator: iterator,
			})
			if err != nil {
				return trace.Wrap(err)
			}
			if len(out.Records) > 0 {
				b.Log.Debugf("Got %v new stream shard records.", len(out.Records))
			}
			if len(out.Records) == 0 {
				if out.NextShardIterator == nil {
					b.Log.Debugf("Shard is closed: %v.", aws.StringValue(shard.ShardId))
					return io.EOF
				}
				iterator = out.NextShardIterator
				continue
			}
			if out.NextShardIterator == nil {
				b.Log.Debugf("Shard is closed: %v.", aws.StringValue(shard.ShardId))
				return io.EOF
			}
			select {
			case <-ctx.Done():
				return trace.ConnectionProblem(ctx.Err(), "context is closing")
			case eventsC <- shardEvent{shardID: shardID, records: out.Records}:
			}
			iterator = out.NextShardIterator
		}
	}
}

// collectActiveShards collects shards
func (b *backend) collectActiveShards(ctx context.Context, streamArn string) ([]*dynamodbstreams.Shard, error) {
	var out []*dynamodbstreams.Shard

	input := &dynamodbstreams.DescribeStreamInput{
		StreamArn: aws.String(streamArn),
	}
	for {
		streamInfo, err := b.Streams.DescribeStreamWithContext(ctx, input)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out = append(out, streamInfo.StreamDescription.Shards...)
		if streamInfo.StreamDescription.LastEvaluatedShardId == nil {
			return filterActiveShards(out), nil
		}
		input.ExclusiveStartShardId = streamInfo.StreamDescription.LastEvaluatedShardId
	}
}

func filterActiveShards(shards []*dynamodbstreams.Shard) []*dynamodbstreams.Shard {
	var active []*dynamodbstreams.Shard
	for i := range shards {
		if shards[i].SequenceNumberRange.EndingSequenceNumber == nil {
			// from https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_DescribeStream.html:
			// > Each shard in the stream has a SequenceNumberRange associated with it.
			// > If the SequenceNumberRange has a StartingSequenceNumber but no EndingSequenceNumber, then the shard is still open (able to receive more stream records).
			// > If both StartingSequenceNumber and EndingSequenceNumber are present, then that shard is closed and can no longer receive more data.
			//
			// Q: From the above, I don't understand why we're filtering out these shards.
			// If the ending sequence number is non-nil, then shard is closed and can't receive more data.
			// But does that mean that we have polled everything?
			// i don't think so!
			active = append(active, shards[i])
		}
	}
	return active
}

func (b *backend) asyncPollShard(ctx context.Context, streamArn string, shard *dynamodbstreams.Shard, eventsC chan shardEvent, initC chan<- error) {
	var err error
	shardID := aws.StringValue(shard.ShardId)
	defer func() {
		if err == nil {
			err = trace.BadParameter("shard %q exited unexpectedly", shardID)
		}
		select {
		case eventsC <- shardEvent{err: err, shardID: shardID}:
		case <-ctx.Done():
			b.Log.Debugf("Context is closing, returning")
			return
		}
	}()
	err = b.pollShard(ctx, streamArn, shard, eventsC, initC)
}

func (b *backend) tableExists(ctx context.Context) (bool, error) {
	_, err := b.Dynamo.DescribeTableWithContext(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(b.TableName),
	})
	if err == nil {
		return true, nil
	}

	aerr, ok := err.(awserr.Error)
	if !ok {
		return false, trace.Wrap(err)
	}
	switch aerr.Code() {
	case dynamodb.ErrCodeResourceNotFoundException:
		return false, nil
	default:
		return false, trace.Wrap(err)
	}
}

func (b *backend) createTable(ctx context.Context) error {
	def := []*dynamodb.AttributeDefinition{
		{
			AttributeName: aws.String(hashKeyKey),
			AttributeType: aws.String("S"),
		},
	}
	elems := []*dynamodb.KeySchemaElement{
		{
			AttributeName: aws.String(hashKeyKey),
			KeyType:       aws.String("HASH"),
		},
	}
	c := dynamodb.CreateTableInput{
		TableName:            aws.String(b.TableName),
		AttributeDefinitions: def,
		KeySchema:            elems,
		// on-demand mode so that auto-scaling will occur as needed
		BillingMode: aws.String("PAY_PER_REQUEST"),
		StreamSpecification: &dynamodb.StreamSpecification{
			StreamEnabled:  aws.Bool(true),
			StreamViewType: aws.String(dynamodb.StreamViewTypeNewImage),
		},
	}
	_, err := b.Dynamo.CreateTableWithContext(ctx, &c)
	if err != nil {
		return trace.Wrap(err)
	}
	b.Log.Infof("Waiting until table %q is created.", b.TableName)
	err = b.Dynamo.WaitUntilTableExistsWithContext(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(b.TableName),
	})
	if err == nil {
		b.Log.Infof("Table %q has been created.", b.TableName)
	}
	return trace.Wrap(err)
}
