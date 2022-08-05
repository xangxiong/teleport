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
	"fmt"
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
	"github.com/aws/aws-sdk-go/service/timestreamwrite"
	log "github.com/sirupsen/logrus"
)

const (
	AwsRegion               = endpoints.UsWest2RegionID
	AwsProfile              = "cloudteam-dev-role"
	DynamoDBTable           = "test-stream-shards-iter-vitor"
	TimestreamDB            = "test-stream-shards-iter-vitor-db"
	TimestreamTable         = "test-stream-shards-iter-vitor"
	HighResPollingPeriod    = 10 * time.Second
	DefaultPollStreamPeriod = time.Second

	// HashKeyKey is a name of the hash key
	HashKeyKey    = "HashKey"
	CreationTime  = "creationTime"
	channelSize   = 1024 * 1024
	maxRetryCount = 128
)

type backend struct {
	Log              *log.Entry
	Dynamo           *dynamodb.DynamoDB
	Streams          *dynamodbstreams.DynamoDBStreams
	TimestreamWrite  *timestreamwrite.TimestreamWrite
	DynamoDBTable    string
	TimestreamDB     string
	TimestreamTable  string
	RetryPeriod      time.Duration
	PollStreamPeriod time.Duration
}

type record struct {
	HashKey string
}

type shardEvent struct {
	records []*dynamodbstreams.Record
	shardID string
	err     error
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
		if len(flag.Args()) != 3 {
			log.Fatalf("Invalid writers configuration")
		}

		keyPrefixPrefix := flag.Arg(1)
		writersCount, err := strconv.Atoi(flag.Arg(2))
		if err != nil {
			log.Fatalf("Invalid writers argument: %s; %s", flag.Arg(2), err)
		}

		if writersCount == 0 {
			log.Fatalf("Number of writes cannot be 0")
		}

		var wg sync.WaitGroup
		for i := 0; i < writersCount; i++ {
			prefix := fmt.Sprintf("%s-%d", keyPrefixPrefix, i)
			wg.Add(1)

			go func() {
				defer wg.Done()
				if err := b.writer(ctx, prefix); err != nil {
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
		Dynamo:           dynamodb.New(session),
		Streams:          dynamodbstreams.New(session),
		TimestreamWrite:  timestreamwrite.New(session),
		DynamoDBTable:    DynamoDBTable,
		TimestreamDB:     TimestreamDB,
		TimestreamTable:  TimestreamTable,
		RetryPeriod:      HighResPollingPeriod,
		PollStreamPeriod: DefaultPollStreamPeriod,
	}, nil
}

func (b *backend) setup(ctx context.Context) error {
	if err := b.setupDynamoDB(ctx); err != nil {
		return trace.Wrap(err)
	}
	if err := b.setupTimestream(ctx); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (b *backend) setupDynamoDB(ctx context.Context) error {
	// create table (with dynamoDB streams enabled) if it does not exist
	exists, err := b.dynamoDBTableExists(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	if exists {
		b.Log.Infof("DynamoDB table %s already exists.", b.DynamoDBTable)
	} else {
		err = b.createDynamoDBTable(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (b *backend) setupTimestream(ctx context.Context) error {
	if err := b.setupTimestreamDatabase(ctx); err != nil {
		return trace.Wrap(err)
	}
	if err := b.setupTimestreamTable(ctx); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (b *backend) setupTimestreamDatabase(ctx context.Context) error {
	exists, err := b.timestreamDatabaseExists(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	if exists {
		b.Log.Infof("Timestream database %s already exists.", b.TimestreamDB)
	} else {
		err = b.createTimestreamDatabase(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (b *backend) setupTimestreamTable(ctx context.Context) error {
	exists, err := b.timestreamTableExists(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	if exists {
		b.Log.Infof("Timestream table %s already exists.", b.TimestreamTable)
	} else {
		err = b.createTimestreamTable(ctx)
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

	recordC := make(chan []*dynamodbstreams.Record, channelSize)

	go func() {
		if err := b.asyncPollStreams(ctx, *streamArn, recordC); err != nil {
			b.Log.Errorf("Stream polling loop exited: %v", err)
		}
	}()

	indexes := make(map[string]int)

	for {
		select {
		case records := <-recordC:
			timestreamRecords := make([]*timestreamwrite.Record, 0)

			for i := range records {
				record := records[i]
				key := *record.Dynamodb.NewImage[HashKeyKey].S
				creationTime := *record.Dynamodb.ApproximateCreationDateTime
				prefix, index := fromKey(key)

				// if there was a previous index, then it must be smaller than the current one just by 1
				if val, ok := indexes[prefix]; ok {
					if val+1 != index {
						log.Fatalf("Error streaming: key=%s, previous index=%d, current index=%d", prefix, val, index)
					}
				}
				indexes[prefix] = index

				timestreamRecord := &timestreamwrite.Record{
					Dimensions: []*timestreamwrite.Dimension{
						{
							Name:  aws.String("prefix"),
							Value: aws.String(prefix),
						},
					},
					MeasureName:      aws.String("index"),
					MeasureValue:     aws.String(strconv.Itoa(index)),
					MeasureValueType: aws.String(timestreamwrite.MeasureValueTypeBigint),
					Time:             aws.String(strconv.FormatInt(creationTime.Unix(), 10)),
					TimeUnit:         aws.String("SECONDS"),
				}

				timestreamRecords = append(timestreamRecords, timestreamRecord)
			}

			output, err := b.TimestreamWrite.WriteRecords(&timestreamwrite.WriteRecordsInput{
				DatabaseName: aws.String(b.TimestreamDB),
				TableName:    aws.String(b.TimestreamTable),
				Records:      timestreamRecords,
			})

			if err != nil {
				return trace.Wrap(err)
			}

			if len(timestreamRecords) != int(*output.RecordsIngested.MemoryStore) {
				b.Log.Warn("Not all timestream records were ingested by the memory store")
			}

		case <-ctx.Done():
			b.Log.Debugf("Closed, returning reader loop.")
			return nil
		}
	}
}

func (b *backend) writer(ctx context.Context, prefix string) error {
	b.Log.Infof("Starting writer on prefix %s", prefix)
	ticker := time.NewTicker(time.Minute)
	start := time.Now()
	recordsCount := 0
	retriesCount := 0
	for {
		select {
		case <-ticker.C:
			throughput := recordsCount / int(time.Since(start).Seconds())
			b.Log.Debugf("records=%d, tput=%d items/s, retries=%d, prefix=%s", recordsCount, throughput, retriesCount, prefix)
		case <-ctx.Done():
			b.Log.Debugf("Closed, returning from writer loop.")
			return nil
		default:
			key := toKey(prefix, recordsCount)
			retries, err := b.putRecord(ctx, key, 0)
			if err != nil {
				return trace.Wrap(err)
			}
			recordsCount++
			retriesCount += retries
		}
	}
}

func toKey(prefix string, index int) string {
	return fmt.Sprintf("%s-%d", prefix, index)
}

func fromKey(key string) (string, int) {
	parts := strings.Split(key, "-")
	prefix := strings.Join([]string{parts[0], parts[1]}, "-")
	indexStr := parts[2]

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		log.Fatalf("Error converting index to int: %s", err)
	}

	return prefix, index
}

func (b *backend) putRecord(ctx context.Context, key string, retryCount int) (int, error) {
	r := record{HashKey: key}
	av, err := dynamodbattribute.MarshalMap(r)
	if err != nil {
		return retryCount, trace.Wrap(err)
	}

	input := &dynamodb.PutItemInput{
		Item:                        av,
		TableName:                   &b.DynamoDBTable,
		ReturnConsumedCapacity:      aws.String("NONE"),
		ReturnItemCollectionMetrics: aws.String("NONE"),
		ReturnValues:                aws.String("NONE"),
	}
	_, err = b.Dynamo.PutItemWithContext(ctx, input)

	if err != nil && retryCount < maxRetryCount {
		// log only if we have already retried this key
		if retryCount > 0 {
			b.Log.Debugf("Error when calling PutItem on key %s (retries %d/%d)", key, retryCount, maxRetryCount)
		}
		return b.putRecord(ctx, key, retryCount+1)
	} else {
		return retryCount, trace.Wrap(err)
	}
}

func (b *backend) asyncPollStreams(ctx context.Context, streamArn string, recordC chan []*dynamodbstreams.Record) error {
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

func (b *backend) pollStreams(externalCtx context.Context, streamArn string, recordC chan []*dynamodbstreams.Record) error {
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
				select {
				case recordC <- event.records:
				case <-ctx.Done():
					b.Log.Debugf("Context is closing, returning")
					return nil
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
		TableName: aws.String(b.DynamoDBTable),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if status.Table.LatestStreamArn == nil {
		return nil, trace.NotFound("No streams found for table %v", b.DynamoDBTable)
	}
	return status.Table.LatestStreamArn, nil
}

func (b *backend) pollShard(ctx context.Context, streamArn string, shard *dynamodbstreams.Shard, eventsC chan shardEvent, initC chan<- error) error {
	shardIterator, err := b.Streams.GetShardIteratorWithContext(ctx, &dynamodbstreams.GetShardIteratorInput{
		ShardId: shard.ShardId,
		// Q: Besides no checkpointing, the shard iterator type is set to LATEST, meaning that there's no worry about retrieving all events.
		// With checkpointing, we would know the last event retrieved from each (known) shard, and could set the shard iterator type to AFTER_SEQUENCE_NUMBER.
		// If the shard is unknown (i.e. no checkpointing info about it), we should probably set the shard iterator type to TRIM_HORIZON, which can retrieve events up-to 24h old.
		ShardIteratorType: aws.String(dynamodbstreams.ShardIteratorTypeTrimHorizon),
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

func (b *backend) dynamoDBTableExists(ctx context.Context) (bool, error) {
	_, err := b.Dynamo.DescribeTableWithContext(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(b.DynamoDBTable),
	})
	return exists(err)
}

func (b *backend) timestreamDatabaseExists(ctx context.Context) (bool, error) {
	_, err := b.TimestreamWrite.DescribeDatabaseWithContext(ctx, &timestreamwrite.DescribeDatabaseInput{
		DatabaseName: aws.String(b.TimestreamDB),
	})
	return exists(err)
}

func (b *backend) timestreamTableExists(ctx context.Context) (bool, error) {
	_, err := b.TimestreamWrite.DescribeTableWithContext(ctx, &timestreamwrite.DescribeTableInput{
		DatabaseName: aws.String(b.TimestreamDB),
		TableName:    aws.String(b.TimestreamTable),
	})
	return exists(err)
}

func exists(err error) (bool, error) {
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

func (b *backend) createDynamoDBTable(ctx context.Context) error {
	def := []*dynamodb.AttributeDefinition{
		{
			AttributeName: aws.String(HashKeyKey),
			AttributeType: aws.String("S"),
		},
	}
	elems := []*dynamodb.KeySchemaElement{
		{
			AttributeName: aws.String(HashKeyKey),
			KeyType:       aws.String("HASH"),
		},
	}
	input := dynamodb.CreateTableInput{
		TableName:            aws.String(b.DynamoDBTable),
		AttributeDefinitions: def,
		KeySchema:            elems,
		// on-demand mode so that auto-scaling will occur as needed
		BillingMode: aws.String("PAY_PER_REQUEST"),
		StreamSpecification: &dynamodb.StreamSpecification{
			StreamEnabled:  aws.Bool(true),
			StreamViewType: aws.String(dynamodb.StreamViewTypeNewImage),
		},
	}
	_, err := b.Dynamo.CreateTableWithContext(ctx, &input)
	if err != nil {
		return trace.Wrap(err)
	}

	b.Log.Infof("Waiting until table %q is created.", b.DynamoDBTable)
	err = b.Dynamo.WaitUntilTableExistsWithContext(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(b.DynamoDBTable),
	})
	if err != nil {
		return trace.Wrap(err)
	} else {
		b.Log.Infof("DynamoDB table %q has been created.", b.DynamoDBTable)
		return nil
	}
}

func (b *backend) createTimestreamDatabase(ctx context.Context) error {
	input := timestreamwrite.CreateDatabaseInput{
		DatabaseName: aws.String(b.TimestreamDB),
	}
	_, err := b.TimestreamWrite.CreateDatabaseWithContext(ctx, &input)
	if err != nil {
		return trace.Wrap(err)
	} else {
		b.Log.Infof("Timestream database %q has been created.", b.TimestreamDB)
		return nil
	}
}

func (b *backend) createTimestreamTable(ctx context.Context) error {
	input := timestreamwrite.CreateTableInput{
		DatabaseName: aws.String(b.TimestreamDB),
		TableName:    aws.String(b.TimestreamTable),
	}
	_, err := b.TimestreamWrite.CreateTableWithContext(ctx, &input)
	if err != nil {
		return trace.Wrap(err)
	} else {
		b.Log.Infof("Timestream table %q has been created.", b.TimestreamTable)
		return nil
	}
}
