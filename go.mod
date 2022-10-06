module github.com/gravitational/teleport

go 1.18

require (
	github.com/ThalesIgnite/crypto11 v1.2.4
	github.com/armon/go-radix v1.0.0
	github.com/coreos/go-semver v0.3.0
	github.com/creack/pty v1.1.18
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/protobuf v1.3.2
	github.com/google/btree v1.0.1
	github.com/google/go-cmp v0.5.8
	github.com/google/uuid v1.3.0
	github.com/gravitational/configure v0.0.0-20180808141939-c3428bd84c23
	github.com/gravitational/kingpin v2.1.11-0.20220901134012-2a1956e29525+incompatible
	github.com/gravitational/oxy v0.0.0-20211213172937-a1ba0900a4c9
	github.com/gravitational/roundtrip v1.0.1
	github.com/gravitational/teleport/api v0.0.0
	github.com/gravitational/trace v1.1.19-0.20220627095334-f3550c86f648
	github.com/gravitational/ttlmap v0.0.0-20171116003245-91fd36b9004c
	github.com/jonboulle/clockwork v0.3.0
	github.com/json-iterator/go v1.1.12
	github.com/mailgun/timetools v0.0.0-20170619190023-f3a7b8ffff47
	github.com/mailgun/ttlmap v0.0.0-20170619185759-c1c17f74874f
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6
	github.com/sirupsen/logrus v1.8.1
	github.com/vulcand/predicate v1.2.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.31.0
	go.opentelemetry.io/otel v1.7.0
	go.opentelemetry.io/otel/trace v1.7.0
	go.uber.org/atomic v1.7.0
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	golang.org/x/net v0.0.0-20220809184613-07c6da5e1ced
	golang.org/x/sys v0.0.0-20220829200755-d48e67d00261
	google.golang.org/appengine v1.6.7
	google.golang.org/grpc v1.49.0
	gopkg.in/square/go-jose.v2 v2.5.1
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/beevik/etree v1.1.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russellhaering/gosaml2 v0.6.1-0.20210916051624-757d23f1bc28 // indirect
	github.com/russellhaering/goxmldsig v1.1.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.31.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.7.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.7.0 // indirect
	go.opentelemetry.io/otel/sdk v1.7.0 // indirect
	go.opentelemetry.io/proto/otlp v0.16.0 // indirect
	golang.org/x/oauth2 v0.0.0-20220808172628-8227340efae7 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220808204814-fd01256a5276 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.0.3 // indirect
)

require (
	cloud.google.com/go/compute v1.8.0 // indirect
	github.com/alecthomas/assert v1.0.0 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gofrs/flock v0.8.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.7.0 // indirect
	github.com/mailgun/minheap v0.0.0-20170619185613-3dbe6c6bf55f // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/miekg/pkcs11 v1.0.3-0.20190429190417-a667d056470f // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/siddontang/go v0.0.0-20180604090527-bdc77568d726
	github.com/thales-e-security/pool v0.0.2 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.7.0 // indirect
	go.opentelemetry.io/otel/metric v0.28.0 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
)

replace (
	github.com/coreos/go-oidc => github.com/gravitational/go-oidc v0.0.6
	github.com/denisenkom/go-mssqldb => github.com/gravitational/go-mssqldb v0.11.1-0.20220509084309-3d41480ef74f
	github.com/dgrijalva/jwt-go v3.2.0+incompatible => github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/go-mysql-org/go-mysql v1.5.0 => github.com/gravitational/go-mysql v1.5.0-teleport.1
	github.com/go-redis/redis/v8 => github.com/gravitational/redis/v8 v8.11.5-0.20220211010318-7af711b76a91
	github.com/gogo/protobuf => github.com/gravitational/protobuf v1.3.2-0.20201123192827-2b9fcfaffcbf
	github.com/gravitational/teleport/api => ./api
	github.com/julienschmidt/httprouter => github.com/gravitational/httprouter v1.3.1-0.20220408074523-c876c5e705a5
	github.com/keys-pub/go-libfido2 => github.com/gravitational/go-libfido2 v1.5.3-0.20220630200200-45a8c53e4500
	github.com/pkg/sftp => github.com/gravitational/sftp v1.13.6-0.20220706192634-fe0df089a5e3
	github.com/russellhaering/gosaml2 => github.com/gravitational/gosaml2 v0.0.0-20220318224559-f06932032ae2
	github.com/sirupsen/logrus => github.com/gravitational/logrus v1.4.4-0.20210817004754-047e20245621
	github.com/vulcand/predicate => github.com/gravitational/predicate v1.2.1
)
