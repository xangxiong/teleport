module github.com/gravitational/teleport

go 1.18

require (
	cloud.google.com/go/firestore v1.6.1
	cloud.google.com/go/iam v0.3.0
	cloud.google.com/go/storage v1.23.0
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.1.3
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysql v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresql v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription v1.0.0
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1
	github.com/Clever/go-utils v0.0.0-20180917210021-2dac0ec6f2ac
	github.com/HdrHistogram/hdrhistogram-go v1.0.1
	github.com/Microsoft/go-winio v0.4.16
	github.com/ThalesIgnite/crypto11 v1.2.4
	github.com/alicebob/miniredis/v2 v2.17.0
	github.com/aquasecurity/libbpfgo v0.2.5-libbpf-0.7.0
	github.com/armon/go-radix v1.0.0
	github.com/aws/aws-sdk-go v1.43.15
	github.com/aws/aws-sdk-go-v2 v1.11.0
	github.com/aws/aws-sdk-go-v2/config v1.10.1
	github.com/aws/aws-sdk-go-v2/credentials v1.6.1
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.8.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.16.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.10.0
	github.com/beevik/etree v1.1.0
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/coreos/go-semver v0.3.0
	github.com/creack/pty v1.1.18
	github.com/denisenkom/go-mssqldb v0.11.0
	github.com/duo-labs/webauthn v0.0.0-20220122034320-81aea484c951
	github.com/dustin/go-humanize v1.0.0
	github.com/elastic/go-elasticsearch/v8 v8.4.0
	github.com/flynn/hid v0.0.0-20190502022136-f1b9b6cc019a
	github.com/flynn/u2f v0.0.0-20180613185708-15554eb68e5d
	github.com/fsouza/fake-gcs-server v1.19.5
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/ghodss/yaml v1.0.0
	github.com/gizak/termui/v3 v3.1.0
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/go-logr/logr v1.2.3
	github.com/go-mysql-org/go-mysql v1.5.0
	github.com/go-redis/redis/v8 v8.11.4
	github.com/gobuffalo/flect v0.2.5
	github.com/gofrs/flock v0.8.1
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.2
	github.com/google/btree v1.0.1
	github.com/google/go-cmp v0.5.8
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.3.0
	github.com/gorilla/websocket v1.4.2
	github.com/gravitational/configure v0.0.0-20180808141939-c3428bd84c23
	github.com/gravitational/form v0.0.0-20151109031454-c4048f792f70
	github.com/gravitational/kingpin v2.1.11-0.20220901134012-2a1956e29525+incompatible
	github.com/gravitational/license v0.0.0-20210218173955-6d8fb49b117a
	github.com/gravitational/oxy v0.0.0-20211213172937-a1ba0900a4c9
	github.com/gravitational/reporting v0.0.0-20210923183620-237377721140
	github.com/gravitational/roundtrip v1.0.1
	github.com/gravitational/teleport/api v0.0.0
	github.com/gravitational/trace v1.1.19-0.20220627095334-f3550c86f648
	github.com/gravitational/ttlmap v0.0.0-20171116003245-91fd36b9004c
	github.com/grpc-ecosystem/go-grpc-middleware/providers/openmetrics/v2 v2.0.0-20220714234348-5d0f5fedefc0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/jackc/pgconn v1.11.0
	github.com/jackc/pgerrcode v0.0.0-20201024163028-a0d42d470451
	github.com/jackc/pgproto3/v2 v2.2.0
	github.com/jackc/pgx/v4 v4.15.0
	github.com/jcmturner/gokrb5/v8 v8.4.2
	github.com/johannesboyne/gofakes3 v0.0.0-20210217223559-02ffa763be97
	github.com/jonboulle/clockwork v0.3.0
	github.com/joshlf/go-acl v0.0.0-20200411065538-eae00ae38531
	github.com/json-iterator/go v1.1.12
	github.com/julienschmidt/httprouter v1.3.0
	github.com/keys-pub/go-libfido2 v1.5.3-0.20220306005615-8ab03fb1ec27
	github.com/mailgun/lemma v0.0.0-20170619173223-4214099fb348
	github.com/mailgun/timetools v0.0.0-20170619190023-f3a7b8ffff47
	github.com/mailgun/ttlmap v0.0.0-20170619185759-c1c17f74874f
	github.com/mattn/go-sqlite3 v1.14.6
	github.com/mdlayher/netlink v1.6.0
	github.com/mitchellh/mapstructure v1.4.1
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6
	github.com/pkg/errors v0.9.1
	github.com/pkg/sftp v1.13.5
	github.com/pquerna/otp v1.3.0
	github.com/prometheus/client_golang v1.13.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.37.0
	github.com/russellhaering/gosaml2 v0.6.1-0.20210916051624-757d23f1bc28
	github.com/russellhaering/goxmldsig v1.1.1
	github.com/sethvargo/go-diceware v0.2.1
	github.com/sirupsen/logrus v1.8.1
	github.com/snowflakedb/gosnowflake v1.6.9
	github.com/stretchr/testify v1.8.0
	github.com/ucarion/urlpath v0.0.0-20200424170820-7ccc79b76bbb
	github.com/vulcand/predicate v1.2.0
	go.etcd.io/etcd/api/v3 v3.5.1
	go.etcd.io/etcd/client/v3 v3.5.1
	go.mongodb.org/mongo-driver v1.10.0
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.35.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.35.0
	go.opentelemetry.io/otel v1.10.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.10.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.10.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.10.0
	go.opentelemetry.io/otel/sdk v1.10.0
	go.opentelemetry.io/otel/trace v1.10.0
	go.opentelemetry.io/proto/otlp v0.19.0
	go.uber.org/atomic v1.7.0
	golang.org/x/crypto v0.0.0-20220919173607-35f4265a4bc0
	golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4
	golang.org/x/net v0.0.0-20220920203100-d0c6ba3f52d9
	golang.org/x/oauth2 v0.0.0-20220909003341-f21342109be1
	golang.org/x/sync v0.0.0-20220907140024-f12130a52804
	golang.org/x/sys v0.0.0-20220919091848-fb04ddd9f9c8
	golang.org/x/term v0.0.0-20220919170432-7a66f970e087
	golang.org/x/text v0.3.7
	golang.org/x/tools v0.1.12
	google.golang.org/api v0.96.0
	google.golang.org/genproto v0.0.0-20220916172020-2692e8806bfa
	google.golang.org/grpc v1.49.0
	google.golang.org/grpc/examples v0.0.0-20210424002626-9572fd6faeae
	google.golang.org/protobuf v1.28.1
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/ini.v1 v1.62.0
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.24.2
	k8s.io/apiextensions-apiserver v0.24.2
	k8s.io/apimachinery v0.24.2
	k8s.io/apiserver v0.24.2
	k8s.io/cli-runtime v0.24.0
	k8s.io/client-go v0.24.2
	k8s.io/klog/v2 v2.60.1
	k8s.io/kubectl v0.24.0
	k8s.io/utils v0.0.0-20220210201930-3a6ce19ff2f9
	sigs.k8s.io/controller-runtime v0.12.3
	sigs.k8s.io/controller-tools v0.9.2
	sigs.k8s.io/yaml v1.3.0
)

require (
	cloud.google.com/go v0.103.0 // indirect
	cloud.google.com/go/compute v1.8.0 // indirect
	github.com/Azure/azure-pipeline-go v0.2.3 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.0.0 // indirect
	github.com/Azure/azure-storage-blob-go v0.14.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.18 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.13 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20200615164410-66371956d46c // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v0.5.1 // indirect
	github.com/MakeNowJust/heredoc v0.0.0-20170808103936-bb23615498cd // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/alecthomas/assert v1.0.0 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
	github.com/apache/arrow/go/arrow v0.0.0-20211112161151-bc219186db40 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.9.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.19.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.6.0 // indirect
	github.com/aws/smithy-go v1.9.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/chai2010/gettext-go v0.0.0-20160711120539-c6fed771bfd5 // indirect
	github.com/cloudflare/cfssl v0.0.0-20190726000631-633726f6bcb7 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/elastic/elastic-transport-go/v8 v8.1.0 // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/exponent-io/jsonpath v0.0.0-20151013193312-d6023ce2651d // indirect
	github.com/fatih/camelcase v1.0.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.1 // indirect
	github.com/go-errors/errors v1.0.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-logr/zapr v1.2.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/go-piv/piv-go v1.10.0 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang-sql/sqlexp v0.0.0-20170517235910-f1bb20e5a188 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/google/flatbuffers v2.0.0+incompatible // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.1.0 // indirect
	github.com/googleapis/gax-go/v2 v2.5.1 // indirect
	github.com/googleapis/go-type-adapters v1.0.0 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20190430165422-3e4dfb77656c // indirect
	github.com/gorilla/handlers v1.5.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gregjones/httpcache v0.0.0-20180305231024-9cad4c3443a7 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.0-rc.2.0.20220308023801-e4a6915ea237 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.7.0 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.10.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.0.0 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/joshlf/testutil v0.0.0-20170608050642-b5d8aa79d93d // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/mailgun/metrics v0.0.0-20150124003306-2b3c4565aafd // indirect
	github.com/mailgun/minheap v0.0.0-20170619185613-3dbe6c6bf55f // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-ieproxy v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.10 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mdlayher/socket v0.1.1 // indirect
	github.com/miekg/pkcs11 v1.0.3-0.20190429190417-a667d056470f // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/montanaflynn/stats v0.6.6 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nsf/termbox-go v0.0.0-20210114135735-d04385b850e8 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/pierrec/lz4/v4 v4.1.11 // indirect
	github.com/pingcap/errors v0.11.5-0.20201126102027-b0a155152ca3 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.8.0 // indirect
	github.com/russross/blackfriday v1.5.2 // indirect
	github.com/ryszard/goskiplist v0.0.0-20150312221310-2dfbae5fcf46 // indirect
	github.com/shabbyrobe/gocovmerge v0.0.0-20190829150210-3e036491d500 // indirect
	github.com/siddontang/go v0.0.0-20180604090527-bdc77568d726 // indirect
	github.com/siddontang/go-log v0.0.0-20180807004314-8d05993dda07 // indirect
	github.com/smartystreets/goconvey v1.7.2 // indirect
	github.com/spf13/cobra v1.4.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.1 // indirect
	github.com/xdg-go/stringprep v1.0.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xlab/treeprint v1.0.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	github.com/yuin/gopher-lua v0.0.0-20200816102855-ee81675732da // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.1 // indirect
	go.opencensus.io v0.23.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.10.0 // indirect
	go.opentelemetry.io/otel/metric v0.31.0 // indirect
	go.starlark.net v0.0.0-20200306205701-8dd3e2ee1dd5 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	golang.org/x/xerrors v0.0.0-20220609144429-65e65417b02f // indirect
	gomodules.xyz/jsonpatch/v2 v2.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	k8s.io/component-base v0.24.2 // indirect
	k8s.io/kube-openapi v0.0.0-20220328201542-3ee0da9b0b42 // indirect
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
	sigs.k8s.io/json v0.0.0-20211208200746-9f7c6b3444d2 // indirect
	sigs.k8s.io/kustomize/api v0.11.4 // indirect
	sigs.k8s.io/kustomize/kyaml v0.13.6 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
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
