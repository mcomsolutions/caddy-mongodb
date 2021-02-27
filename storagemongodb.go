package storagemongodb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/segmentio/ksuid"
	lock "github.com/square/mongo-lock"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	// InactiveLockDuration is when the lock is considered as stale and need to be refreshed
	InactiveLockDuration = 4 * time.Hour

	// LockDuration is lock time duration in seconds
	LockDuration = 600

	// ScanCount is how many scan command might return
	ScanCount int64 = 100

	// Default Values

	// DefaultAESKey needs to be 32 bytes long
	DefaultAESKey = ""

	// DefaultKeyPrefix defines the default prefix in KV store
	DefaultKeyPrefix = "caddytls"

	// DefaultValuePrefix sets a prefix to KV values to check validation
	DefaultValuePrefix = "caddy-storage-MongoDb"

	// DefaultMongoDbHost define the MongoDb instance host
	DefaultMongoDbHost = "127.0.0.1"

	// DefaultMongoDbPort define the MongoDb instance port
	DefaultMongoDbPort = "27017"

	// DefaultDatabase define the mongo database
	DefaultMongoDbDatabase = "caddycerts"

	// DefaultCollection define the mongo database collection
	DefaultMongoDbBucket = "caddycollection"

	// DefaultMongoDbPassword define the MongoDb instance Username, if any
	DefaultMongoDbUsername = ""

	// DefaultMongoDbPassword define the MongoDb instance password, if any
	DefaultMongoDbPassword = ""

	// DefaultMongoDbTimeout define the MongoDb wait time in (s)
	DefaultMongoDbTimeout = 5

	// DefaultMongoDbTLS define the MongoDb TLS connection
	DefaultMongoDbTLS = false

	// DefaultMongoDbTLSInsecure define the MongoDb TLS connection
	DefaultMongoDbTLSInsecure = true

	// Environment Name

	// EnvNameMongoDbHost defines the env variable name to override MongoDb host
	EnvNameMongoDbHost = "CADDY_CLUSTERING_MONGODB_HOST"

	// EnvNameMongoDBPort defines the env variable name to override MongoDb port
	EnvNameMongoDBPort = "CADDY_CLUSTERING_MONGODB_PORT"

	// EnvNameMongoDBDatabase defines the env variable name to override MongoDb db number
	EnvNameMongoDBDatabase = "CADDY_CLUSTERING_MONGODB_DB"

	// EnvNameMongoDBBucketName define the env variable name to
	EnvNameMongoDBBucketName = "CADDY_CLUSTERING_MONGODB_BUCKET_NAME"

	// EnvNameMongoDbUsername defines the env variable name to override MongoDb username
	EnvNameMongoDbUsername = "CADDY_CLUSTERING_MONGODB_USERNAME"

	// EnvNameMongoDbPassword defines the env variable name to override MongoDb password
	EnvNameMongoDbPassword = "CADDY_CLUSTERING_MONGODB_PASSWORD"

	// EnvNameMongoDbTimeout defines the env variable name to override MongoDb wait timeout for dial, read, write
	EnvNameMongoDbTimeout = "CADDY_CLUSTERING_MONGODB_TIMEOUT"

	// EnvNameAESKey defines the env variable name to override AES key
	EnvNameAESKey = "CADDY_CLUSTERING_MONGODB_AESKEY"

	// EnvNameKeyPrefix defines the env variable name to override KV key prefix
	EnvNameKeyPrefix = "CADDY_CLUSTERING_MONGODB_KEYPREFIX"

	// EnvNameValuePrefix defines the env variable name to override KV value prefix
	EnvNameValuePrefix = "CADDY_CLUSTERING_MONGODB_VALUEPREFIX"

	// EnvNameTLSEnabled defines the env variable name to whether enable MongoDb TLS Connection or not
	EnvNameTLSEnabled = "CADDY_CLUSTERING_MONGODB_TLS"

	// EnvNameTLSInsecure defines the env variable name to whether verify MongoDb TLS Connection or not
	EnvNameTLSInsecure = "CADDY_CLUSTERING_MONGODB_TLS_INSECURE"
)

// StorageMongodb contain MongoDb client, and plugin option
type StorageMongodb struct {
	ClientMongo *mongo.Client
	lockManager *lock.Client
	Logger      *zap.SugaredLogger
	ctx         context.Context
	IPAddress   net.IP

	Host         string `json:"host"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Port         string `json:"port"`
	DataBaseName string `json:"database"`
	BucketName   string `json:"bucket"`
	Timeout      int    `json:"timeout"`
	KeyPrefix    string `json:"key_prefix"`
	ValuePrefix  string `json:"value_prefix"`
	AesKey       string `json:"aes_key"`
	TlsEnabled   bool   `json:"tls_enabled"`
	TlsInsecure  bool   `json:"tls_insecure"`

	locks *sync.Map
}

// StorageData describe the data that is stored in KV storage
type StorageData struct {
	Value    []byte    `json:"value"`
	Modified time.Time `json:"modified"`
}

func init() {
	caddy.RegisterModule(StorageMongodb{})
}

// register caddy module with ID caddy.storage.MongoDb
func (StorageMongodb) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.storagemongodb",
		New: func() caddy.Module {
			return new(StorageMongodb)
		},
	}
}

// CertMagicStorage converts s to a certmagic.Storage instance.
func (rd *StorageMongodb) CertMagicStorage() (certmagic.Storage, error) {
	return rd, nil
}

func (rd *StorageMongodb) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		key := d.Val()
		var value string

		if !d.Args(&value) {
			continue
		}

		switch key {
		case "host":
			if value != "" {
				rd.Host = value
			} else {
				rd.Host = DefaultMongoDbHost
			}
		case "username":
			if value != "" {
				rd.Username = value
			} else {
				rd.Username = DefaultMongoDbUsername
			}
		case "password":
			if value != "" {
				rd.Password = value
			} else {
				rd.Password = DefaultMongoDbPassword
			}
		case "port":
			if value != "" {
				rd.Port = value
			} else {
				rd.Port = DefaultMongoDbPort
			}
		case "database":
			if value != "" {
				rd.DataBaseName = value
			} else {
				rd.DataBaseName = DefaultMongoDbDatabase
			}
		case "bucket":
			if value != "" {
				rd.BucketName = value
			} else {
				rd.BucketName = DefaultMongoDbBucket
			}
		case "timeout":
			if value != "" {
				timeParse, err := strconv.Atoi(value)
				if err == nil {
					rd.Timeout = timeParse
				} else {
					rd.Timeout = DefaultMongoDbTimeout
				}
			} else {
				rd.Timeout = DefaultMongoDbTimeout
			}
		case "key_prefix":
			if value != "" {
				rd.KeyPrefix = value
			} else {
				rd.KeyPrefix = DefaultKeyPrefix
			}
		case "value_prefix":
			if value != "" {
				rd.ValuePrefix = value
			} else {
				rd.ValuePrefix = DefaultValuePrefix
			}
		case "aes_key":
			if value != "" {
				rd.AesKey = value
			} else {
				rd.AesKey = DefaultAESKey
			}
		case "tls_enabled":
			if value != "" {
				tlsParse, err := strconv.ParseBool(value)
				if err == nil {
					rd.TlsEnabled = tlsParse
				} else {
					rd.TlsEnabled = DefaultMongoDbTLS
				}
			} else {
				rd.TlsEnabled = DefaultMongoDbTLS
			}
		case "tls_insecure":
			if value != "" {
				tlsInsecureParse, err := strconv.ParseBool(value)
				if err == nil {
					rd.TlsInsecure = tlsInsecureParse
				} else {
					rd.TlsInsecure = DefaultMongoDbTLSInsecure
				}
			} else {
				rd.TlsInsecure = DefaultMongoDbTLSInsecure
			}
		}
	}
	return nil
}

func (rd *StorageMongodb) Provision(ctx caddy.Context) error {
	rd.Logger = ctx.Logger(rd).Sugar()
	rd.GetConfigValue()
	rd.Logger.Info("TLS Storage are using Mongodb, on " + rd.Host)
	if err := rd.BuildMongoDbClient(); err != nil {
		return err
	}
	rd.IPAddress = rd.GetOutboundIP()
	return nil
}

// GetConfigValue get Config value from env, if already been set by Caddyfile, don't overwrite
func (rd *StorageMongodb) GetConfigValue() {
	logger, _ := zap.NewProduction()
	defer logger.Sync() // flushes buffer, if any
	rd.Logger = logger.Sugar()
	rd.Logger.Debugf("GetConfigValue [%s]:%s", "pre", rd)
	rd.Logger.Info("Estoy en la funcion GetConfigValue. Esta funcion se tiene que recodificar")

	rd.Host = configureString(rd.Host, EnvNameMongoDbHost, DefaultMongoDbHost)
	rd.Username = configureString(rd.Username, EnvNameMongoDbUsername, DefaultMongoDbUsername)
	rd.Password = configureString(rd.Password, EnvNameMongoDbPassword, DefaultMongoDbPassword)
	rd.Port = configureString(rd.Port, EnvNameMongoDBPort, DefaultMongoDbPort)
	rd.DataBaseName = configureString(rd.DataBaseName, EnvNameMongoDBDatabase, DefaultMongoDbDatabase)
	rd.BucketName = configureString(rd.BucketName, EnvNameMongoDBBucketName, DefaultMongoDbBucket)

	rd.Timeout = configureInt(rd.Timeout, EnvNameMongoDbTimeout, DefaultMongoDbTimeout)
	rd.TlsEnabled = configureBool(rd.TlsEnabled, EnvNameTLSEnabled, DefaultMongoDbTLS)
	rd.TlsInsecure = configureBool(rd.TlsInsecure, EnvNameTLSInsecure, DefaultMongoDbTLSInsecure)
	rd.KeyPrefix = configureString(rd.KeyPrefix, EnvNameKeyPrefix, DefaultKeyPrefix)
	rd.ValuePrefix = configureString(rd.ValuePrefix, EnvNameValuePrefix, DefaultValuePrefix)
	rd.AesKey = configureString(rd.AesKey, EnvNameAESKey, DefaultAESKey)
	rd.Logger.Debugf("GetConfigValue [%s]:%s", "post", rd)
}

// helper function to prefix key
func (rd *StorageMongodb) prefixKey(key string) string {
	return path.Join(rd.KeyPrefix, key)
}

/**
 * Build a new mongo client, and connect the client to use. The client has a timeout of 10 seconds for operations
 */
func (rd *StorageMongodb) BuildMongoDbClient() error {
	ConnectionString := "mongodb://"
	if len(rd.Username) > 0 {
		ConnectionString = ConnectionString + rd.Username + ":" + rd.Password + "@"
	}
	ConnectionString = ConnectionString + rd.Host
	p, err := strconv.Atoi(rd.Port)
	if err == nil && p != -1 {
		ConnectionString = ConnectionString + ":" + rd.Port
	}
	opt := options.Client()
	opt.ApplyURI(ConnectionString)
	opt.SetMaxPoolSize(5)
	MongodbClient, e := mongo.NewClient(opt)
	if e != nil {
		return fmt.Errorf("unable to connect to database %s by error %s", ConnectionString, e)
	}

	/**
	 * En el siguiente bloque conecto a mongodb
	 */
	rd.ctx, _ = context.WithTimeout(context.Background(), time.Duration(rd.Timeout)*time.Second)
	err = MongodbClient.Connect(rd.ctx)
	if err != nil {
		return fmt.Errorf("unable to connect to database %s", ConnectionString)
	}
	rd.ClientMongo = MongodbClient

	c, err := rd.getLockEngine()
	if err != nil {
		return fmt.Errorf("unable to create lockManager %s", err)
	}
	rd.lockManager = c
	rd.locks = &sync.Map{}
	return nil
}

// Store values at key
func (rd StorageMongodb) Store(key string, value []byte) error {
	data := &StorageData{
		Value:    value,
		Modified: time.Now(),
	}

	encryptedValue, err := rd.EncryptStorageData(data)
	if err != nil {
		return fmt.Errorf("unable to encode data for %v: %v", key, err)
	}

	bucket, err := rd.getBucket()
	if err != nil {
		return fmt.Errorf("unable to store data for %v: %v", key, err)
	}

	uploadOpts := options.GridFSUpload().SetMetadata(bson.D{{"entered", time.Now()}})
	uploadStream, err := bucket.OpenUploadStream(rd.prefixKey(key), uploadOpts)
	if err != nil {
		return fmt.Errorf("unable to store data for %v: %v", key, err)
	}
	defer func() {
		if err = uploadStream.Close(); err != nil {
			fmt.Errorf("unable to store data for %v: %v", key, err)
		}
	}()

	if err = uploadStream.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("unable to store data for %v: %v", key, err)
	}

	if _, err = uploadStream.Write(encryptedValue); err != nil {
		return fmt.Errorf("unable to store data for %v: %v", key, err)
	}
	return nil
}

// Load retrieves the value at key.
func (rd StorageMongodb) Load(key string) ([]byte, error) {
	data, err := rd.getDataDecrypted(key)
	if err != nil {
		return nil, err
	}
	return data.Value, nil
}

// Delete deletes key.
func (rd StorageMongodb) Delete(key string) error {
	_, err := rd.getData(key)
	if err != nil {
		return err
	}
	bucket, err := rd.getBucket()
	if err != nil {
		return fmt.Errorf("unable to store data for %v: %v", key, err)
	}
	cursor, err := bucket.Find(bson.D{{"filename", rd.prefixKey(key)}})
	if err != nil {
		return fmt.Errorf("unable to delete data for key %s: %v", key, err)
	}
	defer func() {
		if err := cursor.Close(rd.ctx); err != nil {
			fmt.Errorf("unable to close cursor for key %s: %v", key, err)
		}
	}()
	for cursor.Next(rd.ctx) {
		var result bson.M
		if err = cursor.Decode(&result); err != nil {
			return fmt.Errorf("unable to decode data to delete for key %s: %v", key, err)
		}
		bucket.Delete(result["_id"])
	}
	return nil
}

// Exists returns true if the key exists
func (rd StorageMongodb) Exists(key string) bool {
	bucket, err := rd.getBucket()
	if err != nil {
		rd.Logger.Error(err)
		return false
	}
	cursor, err := bucket.Find(bson.D{{"filename", rd.prefixKey(key)}})
	if err != nil {
		rd.Logger.Error(err)
		return false
	}
	defer func() {
		if err := cursor.Close(rd.ctx); err != nil {
			rd.Logger.Error(err)
		}
	}()
	for cursor.Next(rd.ctx) {
		var result bson.M
		if err = cursor.Decode(&result); err != nil {
			rd.Logger.Error(err)
		}
		if result["filename"] == key {
			return true
		}
	}
	return false
}

// List returns all keys that match prefix.
func (rd StorageMongodb) List(prefix string, recursive bool) ([]string, error) {
	var keysFound []string
	var tempKeys []string
	//	var firstPointer uint64 = 0
	//	var pointer uint64 = 0
	var search string

	// assuming we want to list all keys
	if prefix == "*" {
		search = "^" + rd.prefixKey("") + "."
	} else if len(strings.TrimSpace(prefix)) == 0 {
		search = "^" + rd.prefixKey("") + "."
	} else {
		search = "^" + rd.prefixKey(prefix) + "."
	}
	filter := bson.M{"filename": primitive.Regex{Pattern: search, Options: "ims"}}
	bucket, err := rd.getBucket()
	if err != nil {
		return nil, err
	}
	cursor, err := bucket.Find(filter)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := cursor.Close(rd.ctx); err != nil {
			rd.Logger.Error(err.Error())
		}
	}()
	for cursor.Next(rd.ctx) {
		var result bson.M
		if err = cursor.Decode(&result); err != nil {
			fmt.Println(err)
		}
		filename := fmt.Sprintf("%v", result["filename"])
		tempKeys = append(tempKeys, filename)
		fmt.Printf("%s\n", filename)
	}

	if prefix == "*" || len(strings.TrimSpace(prefix)) == 0 {
		search = rd.KeyPrefix
	} else {
		search = rd.prefixKey(prefix)
	}

	// remove default prefix from keys
	for _, key := range tempKeys {
		if strings.HasPrefix(key, search) {
			key = strings.TrimPrefix(key, rd.KeyPrefix+"/")
			keysFound = append(keysFound, key)
		}
	}

	// if recursive wanted, or wildcard/empty prefix, just return all keys prefix is empty
	if recursive || prefix == "*" || len(strings.TrimSpace(prefix)) == 0 {
		return keysFound, nil
	}

	// for non-recursive split path and look for unique keys just under given prefix
	keysMap := make(map[string]bool)
	for _, key := range keysFound {
		dir := strings.Split(strings.TrimPrefix(key, prefix+"/"), "/")
		keysMap[dir[0]] = true
	}

	keysFound = make([]string, 0)
	for key := range keysMap {
		keysFound = append(keysFound, path.Join(prefix, key))
	}

	fmt.Printf("Lo que voy a regresar con el prefix: %s y el recursive es %t \n", prefix, recursive)
	for i := range keysFound {
		fmt.Printf("%s\n", keysFound[i])
	}
	return keysFound, nil
}

// Stat returns information about key.
func (rd StorageMongodb) Stat(key string) (certmagic.KeyInfo, error) {
	data, err := rd.getDataDecrypted(key)

	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   data.Modified,
		Size:       int64(len(data.Value)),
		IsTerminal: false,
	}, nil
}

// getData return data from MongoDb by key as it is
func (rd StorageMongodb) getData(key string) ([]byte, error) {
	fileBuffer := bytes.NewBuffer(nil)
	bucket, err := rd.getBucket()
	if err != nil {
		return nil, fmt.Errorf("unable to open bucket for getData %s: %v", key, err)
	}

	_, err = bucket.DownloadToStreamByName(rd.prefixKey(key), fileBuffer)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain data for %s: %v", key, err)
	}
	if fileBuffer.Len() <= 0 {
		return nil, certmagic.ErrNotExist(fmt.Errorf("key %s does not exist", key))
	}
	return fileBuffer.Bytes(), nil
}

// getDataDecrypted return StorageData by key
func (rd StorageMongodb) getDataDecrypted(key string) (*StorageData, error) {
	data, err := rd.getData(key)

	if err != nil {
		return nil, err
	}
	decryptedData, err := rd.DecryptStorageData(data)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt data for %s: %v", key, err)
	}
	return decryptedData, nil
}

// Lock is to lock value
func (rd StorageMongodb) Lock(ctx context.Context, key string) error {
	lockName := rd.prefixKey(key) + ".lock"

	if lockID, exists := rd.locks.Load(key); exists {
		var f lock.Filter
		f.LockId = lockID.(string)
		LockStatus, err := rd.lockManager.Status(rd.ctx, f)
		if err != nil {
			return fmt.Errorf("There is an error try to get lock %s whit the key %s", err.Error(), key)
		}
		if len(LockStatus) > 0 {
			if LockStatus[0].TTL > 0 {
				rd.Logger.Infof("Estoy en el bloque que tengo que renovar el lock")
				_, err := rd.lockManager.Renew(rd.ctx, f.LockId, LockDuration)
				if err != nil {
					return err
				}
				return nil
			} else if LockStatus[0].TTL <= 0 {
				rd.lockManager.Unlock(rd.ctx, f.LockId)
				rd.locks.Delete(key)
			}
		}
	}
	LockID := ksuid.New().String()
	var LockDetails lock.LockDetails
	LockDetails.TTL = LockDuration
	LockDetails.Host = rd.IPAddress.String()
	err := rd.lockManager.XLock(rd.ctx, lockName, LockID, LockDetails)
	if err != nil {
		return fmt.Errorf("can't obtain lock, it still being held by other, %v. The lock id with fail is: %s", err, LockID)
	}
	rd.locks.Store(key, LockID)
	return nil
}

// Unlock is to unlock value
func (rd StorageMongodb) Unlock(key string) error {
	if lockID, exists := rd.locks.Load(key); exists {
		_, err := rd.lockManager.Unlock(rd.ctx, lockID.(string))
		if err != nil {
			return fmt.Errorf("we don't have this lock anymore, %v", err)
		}
		rd.locks.Delete(key)
	}
	return nil
}

/**
 * Regresa la llave para encriptacion como un arreglo de bytes
 */
func (rd *StorageMongodb) GetAESKeyByte() []byte {
	return []byte(rd.AesKey)
}

/**
 * La utilizo para recuperar el bucket que se utiliza para guardar la informacion de los certificados en la base de datos
 */
func (rd StorageMongodb) getBucket() (*gridfs.Bucket, error) {
	db := rd.ClientMongo.Database(rd.DataBaseName)
	opt := options.GridFSBucket().SetName(rd.BucketName)
	bucket, err := gridfs.NewBucket(db, opt)
	return bucket, err
}

/**
 * Crea el lockEngine para poder utilizarlo
 */
func (rd StorageMongodb) getLockEngine() (*lock.Client, error) {
	db := rd.ClientMongo.Database(rd.DataBaseName)
	col := db.Collection(rd.BucketName + ".lock")

	c := lock.NewClient(col)
	err := c.CreateIndexes(rd.ctx)
	if err != nil {
		return nil, err
	}
	return c, nil
}

/**
 * Recupera la direccion ip utilizada para conectarse al exteriror
 */
func (rd StorageMongodb) GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// interface guard
var (
	_ caddy.StorageConverter = (*StorageMongodb)(nil)
	_ caddyfile.Unmarshaler  = (*StorageMongodb)(nil)
	_ caddy.Provisioner      = (*StorageMongodb)(nil)
)

func (rd StorageMongodb) String() string {
	strVal, _ := json.Marshal(rd)
	return string(strVal)
}

func configureBool(value bool, envVariableName string, valueDefault bool) bool {
	if value {
		return value
	}
	if envVariableName != "" {
		valueEnvStr := os.Getenv(envVariableName)
		if valueEnvStr != "" {
			valueEnv, err := strconv.ParseBool(os.Getenv(envVariableName))
			if err == nil {
				return valueEnv
			}
		}
	}
	return valueDefault
}

func configureInt(value int, envVariableName string, valueDefault int) int {
	if value != 0 {
		return value
	}
	if envVariableName != "" {
		valueEnvStr := os.Getenv(envVariableName)
		if valueEnvStr != "" {
			valueEnv, err := strconv.Atoi(os.Getenv(envVariableName))
			if err == nil {
				return valueEnv
			}
		}
	}
	return valueDefault
}

func configureString(value string, envVariableName string, valueDefault string) string {
	if value != "" {
		return value
	}
	if envVariableName != "" {
		valueEnvStr := os.Getenv(envVariableName)
		if valueEnvStr != "" {
			return valueEnvStr
		}
	}
	return valueDefault
}
