package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"
)

type S3 struct {
	Logger *zap.Logger

	// S3
	Client    *minio.Client
	Host      string `json:"host"`
	Bucket    string `json:"bucket"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Prefix    string `json:"prefix"`
	Region    string `json:"region"`
	Secure    bool   `json:"secure"`
	Endpoint  string `json:"endpoint"`

	// EncryptionKey is optional. If you do not wish to encrypt your certficates and key inside the S3 bucket, leave it empty.
	// This should be a 32-byte key for NaCl secretbox encryption.
	EncryptionKey []byte `json:"encryption_key"`

	iowrap IO
}

func init() {
	caddy.RegisterModule(new(S3))
}

func (s3 *S3) Provision(caddyCtx caddy.Context) error {
	s3.Logger = caddyCtx.Logger(s3)

	// Set defaults
	if s3.Prefix == "" {
		s3.Prefix = "acme"
	}
	
	if s3.Secure == false {
		s3.Logger.Warn("S3 client is configured to use insecure connection (HTTP)")
	} else {
		// Default to secure if not specified
		s3.Secure = true
	}
	
	// Check for environment variables if credentials not provided
	if s3.AccessKey == "" {
		s3.AccessKey = os.Getenv("AWS_ACCESS_KEY_ID")
		if s3.AccessKey == "" {
			s3.Logger.Debug("No access key provided in config, checking for AWS_ACCESS_KEY_ID environment variable")
		}
	}
	
	if s3.SecretKey == "" {
		s3.SecretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
		if s3.SecretKey == "" {
			s3.Logger.Debug("No secret key provided in config, checking for AWS_SECRET_ACCESS_KEY environment variable")
		}
	}
	
	// Use custom endpoint if provided
	endpoint := s3.Host
	if s3.Endpoint != "" {
		endpoint = s3.Endpoint
	}

	// S3 Client options
	options := &minio.Options{
		Secure: s3.Secure,
		Region: s3.Region,
	}
	
	// Set credentials if provided
	if s3.AccessKey != "" && s3.SecretKey != "" {
		options.Creds = credentials.NewStaticV4(s3.AccessKey, s3.SecretKey, "")
	} else {
		// Use IAM role or other AWS credential providers
		s3.Logger.Info("No static credentials provided, using IAM role or environment variables")
		options.Creds = credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvAWS{},
			&credentials.IAM{
				Client: &http.Client{
					Timeout: 5 * time.Second,
				},
			},
		})
	}

	// Create S3 client
	client, err := minio.New(endpoint, options)
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}

	s3.Client = client
	
	// Check if bucket exists
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	exists, err := s3.Client.BucketExists(ctx, s3.Bucket)
	if err != nil {
		return fmt.Errorf("failed to check if bucket exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("bucket %s does not exist", s3.Bucket)
	}

	// Configure encryption
	if len(s3.EncryptionKey) == 0 {
		s3.Logger.Info("Clear text certificate storage active")
		s3.iowrap = &CleartextIO{}
	} else if len(s3.EncryptionKey) != 32 {
		s3.Logger.Error("encryption key must have exactly 32 bytes")
		return errors.New("encryption key must have exactly 32 bytes")
	} else {
		s3.Logger.Info("Encrypted certificate storage active")
		sb := &SecretBoxIO{}
		copy(sb.SecretKey[:], s3.EncryptionKey)
		s3.iowrap = sb
	}

	return nil
}

func (s3 *S3) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.s3",
		New: func() caddy.Module {
			return new(S3)
		},
	}
}

var (
	LockExpiration   = 2 * time.Minute
	LockPollInterval = 1 * time.Second
	LockTimeout      = 15 * time.Second
)

// objectExists checks if an object exists in the S3 bucket
func (s3 *S3) objectExists(ctx context.Context, objectName string) (bool, error) {
    _, err := s3.Client.StatObject(ctx, s3.Bucket, objectName, minio.StatObjectOptions{})
    if err != nil {
        if strings.Contains(err.Error(), "key does not exist") || 
           strings.Contains(err.Error(), "NoSuchKey") ||
           minio.ToErrorResponse(err).Code == "NoSuchKey" {
            return false, nil
        }
        return false, fmt.Errorf("failed to check if object exists: %w", err)
    }
    return true, nil
}

func (s3 *S3) Lock(ctx context.Context, key string) error {
    lockName := s3.objLockName(key)
    s3.Logger.Info(fmt.Sprintf("Lock: attempting to lock %v", s3.objName(key)))
    var startedAt = time.Now()

    // Loop trying to acquire the lock
    for {
        // First check if the lock file exists
        s3.Logger.Debug(fmt.Sprintf("Lock: checking if lock file exists for %v", s3.objName(key)))
        
        // Use the parent context for timeout control
        checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
        exists, statErr := s3.objectExists(checkCtx, lockName)
        checkCancel()
        
        if statErr != nil {
            s3.Logger.Error(fmt.Sprintf("Lock: error checking if lock file exists: %v", statErr))
            // If check fails and we've timed out, return error
            if startedAt.Add(LockTimeout).Before(time.Now()) {
                return fmt.Errorf("failed to check if lock file exists: %w", statErr)
            }
            time.Sleep(LockPollInterval)
            continue
        }
        
        s3.Logger.Debug(fmt.Sprintf("Lock: lock file exists check result: %v", exists))
        
        if !exists {
            // File doesn't exist, try to create it
            s3.Logger.Info(fmt.Sprintf("Lock: lock file confirmed not to exist, creating for %v", lockName))
            
            // Use atomic operation to ensure only one process creates the lock file
            createCtx, createCancel := context.WithTimeout(ctx, 10*time.Second)
            createErr := s3.putLockFile(createCtx, key)
            createCancel()
            
            if createErr != nil {
                s3.Logger.Error(fmt.Sprintf("Lock: failed to create lock file: %v", createErr))
                
                // If error is due to file already existing, continue the loop and try again
                if strings.Contains(createErr.Error(), "PreconditionFailed") || 
                   strings.Contains(createErr.Error(), "ConditionNotMet") ||
                   strings.Contains(createErr.Error(), "ObjectAlreadyExists") {
                    s3.Logger.Debug("Lock: lock file was created by another process, retrying")
                    time.Sleep(LockPollInterval)
                    continue
                }
                
                // Return other errors
                return fmt.Errorf("failed to create lock file: %w", createErr)
            }
            
            s3.Logger.Info(fmt.Sprintf("Lock: successfully created lock file for %v", lockName))
            return nil
        }
        
        // File exists, try to get its content
        getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
        obj, err := s3.Client.GetObject(getCtx, s3.Bucket, lockName, minio.GetObjectOptions{})
        
        if err != nil {
            getCancel() // Cancel context if error occurs
            s3.Logger.Error(fmt.Sprintf("Lock: error getting lock file that should exist: %v", err))
            
            // If timed out, return error
            if startedAt.Add(LockTimeout).Before(time.Now()) {
                return fmt.Errorf("failed to get lock file after confirming existence: %w", err)
            }
            time.Sleep(LockPollInterval)
            continue
        }
        
        // Ensure object is closed to prevent goroutine leaks
        defer obj.Close()
        defer getCancel() // Ensure context is cancelled when done
        
        s3.Logger.Debug(fmt.Sprintf("Lock: reading lock file content for %v", s3.objName(key)))
        buf, err := io.ReadAll(obj)
        if err != nil {
            s3.Logger.Error(fmt.Sprintf("Lock: error reading lock file content: %v", err))
            // If timed out, return error
            if startedAt.Add(LockTimeout).Before(time.Now()) {
                return fmt.Errorf("failed to read lock file content: %w", err)
            }
            time.Sleep(LockPollInterval)
            continue
        }
        
        s3.Logger.Debug(fmt.Sprintf("Lock: parsing lock timestamp for %v: %s", s3.objName(key), string(buf)))
        lt, err := time.Parse(time.RFC3339, string(buf))
        if err != nil {
            // Lock file format is invalid, try to overwrite
            s3.Logger.Info(fmt.Sprintf("Lock: invalid timestamp in lock file, attempting to overwrite for %v", s3.objName(key)))
            
            // Use a new context for overwriting
            overwriteCtx, overwriteCancel := context.WithTimeout(ctx, 10*time.Second)
            createErr := s3.putLockFile(overwriteCtx, key)
            overwriteCancel()
            
            if createErr != nil {
                s3.Logger.Error(fmt.Sprintf("Lock: failed to overwrite invalid lock file: %v", createErr))
                // If timed out, return error
                if startedAt.Add(LockTimeout).Before(time.Now()) {
                    return fmt.Errorf("failed to overwrite invalid lock file: %w", createErr)
                }
                time.Sleep(LockPollInterval)
                continue
            }
            return nil
        }
        
        if lt.Add(LockExpiration).Before(time.Now()) {
            // Existing lock file has expired, try to overwrite
            s3.Logger.Info(fmt.Sprintf("Lock: lock file expired, attempting to overwrite for %v", s3.objName(key)))
            
            // Use a new context for overwriting
            overwriteCtx, overwriteCancel := context.WithTimeout(ctx, 10*time.Second)
            createErr := s3.putLockFile(overwriteCtx, key)
            overwriteCancel()
            
            if createErr != nil {
                s3.Logger.Error(fmt.Sprintf("Lock: failed to overwrite expired lock file: %v", createErr))
                // If timed out, return error
                if startedAt.Add(LockTimeout).Before(time.Now()) {
                    return fmt.Errorf("failed to overwrite expired lock file: %w", createErr)
                }
                time.Sleep(LockPollInterval)
                continue
            }
            return nil
        }

        // Lock is still valid, wait
        s3.Logger.Debug(fmt.Sprintf("Lock: lock is still valid for %v, waiting", s3.objName(key)))
        
        if startedAt.Add(LockTimeout).Before(time.Now()) {
            s3.Logger.Error(fmt.Sprintf("Lock: timeout waiting for lock for %v", s3.objName(key)))
            return errors.New("acquiring lock failed: timeout waiting for lock")
        }
        time.Sleep(LockPollInterval)
    }
}

func (s3 *S3) putLockFile(ctx context.Context, key string) error {
	// Object does not exist, we're creating a lock file.
	lockName := s3.objLockName(key)
	s3.Logger.Debug(fmt.Sprintf("putLockFile: creating lock file for %v", lockName))
	
	// Create lock content with current timestamp
	lockContent := time.Now().Format(time.RFC3339)
	r := bytes.NewReader([]byte(lockContent))
	
	// Use the parent context to respect cancellation
	s3.Logger.Debug(fmt.Sprintf("putLockFile: putting object to bucket %s with key %s", s3.Bucket, lockName))
	
	// Try to use PutObject with conditions to ensure atomicity
	opts := minio.PutObjectOptions{
		// Set content type for better metadata
		ContentType: "text/plain",
	}
	
	_, err := s3.Client.PutObject(ctx, s3.Bucket, lockName, r, int64(r.Len()), opts)
	if err != nil {
		s3.Logger.Error(fmt.Sprintf("putLockFile: failed to put lock file: %v", err))
		return fmt.Errorf("failed to create lock file: %w", err)
	} else {
		s3.Logger.Debug(fmt.Sprintf("putLockFile: successfully created lock file for %v", lockName))
	}
	return nil
}

func (s3 *S3) Unlock(ctx context.Context, key string) error {
	lockName := s3.objLockName(key)
	s3.Logger.Info(fmt.Sprintf("Release lock: %v", s3.objName(key)))
	
	// Use the parent context to respect cancellation
	removeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	err := s3.Client.RemoveObject(removeCtx, s3.Bucket, lockName, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}
	return nil
}

func (s3 *S3) Store(ctx context.Context, key string, value []byte) error {
	r := s3.iowrap.ByteReader(value)
	objName := s3.objName(key)
	s3.Logger.Info(fmt.Sprintf("Store: %v, %v bytes", objName, len(value)))
	
	// Use the parent context to respect cancellation
	storeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	_, err := s3.Client.PutObject(storeCtx,
		s3.Bucket,
		objName,
		r,
		int64(r.Len()),
		minio.PutObjectOptions{},
	)
	
	if err != nil {
		return fmt.Errorf("failed to store object %s: %w", objName, err)
	}
	return nil
}

func (s3 *S3) Load(ctx context.Context, key string) ([]byte, error) {
	objName := s3.objName(key)
	s3.Logger.Info(fmt.Sprintf("Load: %v", objName))
	
	// Use the parent context to respect cancellation
	loadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	r, err := s3.Client.GetObject(loadCtx, s3.Bucket, objName, minio.GetObjectOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "The specified key does not exist") ||
		   minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("failed to get object %s: %w", objName, err)
	}
	
	// Always ensure the object is closed to prevent goroutine leaks
	defer r.Close()
	
	if r != nil {
		// Check if the object exists
		stat, err := r.Stat()
		if err != nil {
			er := minio.ToErrorResponse(err)
			if er.StatusCode == 404 {
				return nil, fs.ErrNotExist
			}
			return nil, fmt.Errorf("failed to stat object %s: %w", objName, err)
		}
		
		// Check if the object is empty
		if stat.Size == 0 {
			return []byte{}, nil
		}
	}
	
	// Create a wrapped reader that properly handles the object stream
	wrappedReader := s3.iowrap.WrapReader(r)
	buf, err := io.ReadAll(wrappedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read object %s: %w", objName, err)
	}
	return buf, nil
}

func (s3 *S3) Delete(ctx context.Context, key string) error {
	objName := s3.objName(key)
	s3.Logger.Info(fmt.Sprintf("Delete: %v", objName))
	
	// Use the parent context to respect cancellation
	deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	err := s3.Client.RemoveObject(deleteCtx, s3.Bucket, objName, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete object %s: %w", objName, err)
	}
	return nil
}

func (s3 *S3) Exists(ctx context.Context, key string) bool {
	objName := s3.objName(key)
	s3.Logger.Info(fmt.Sprintf("Exists: %v", objName))
	
	// Use the parent context to respect cancellation
	existsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	_, err := s3.Client.StatObject(existsCtx, s3.Bucket, objName, minio.StatObjectOptions{})
	if err != nil {
		s3.Logger.Debug(fmt.Sprintf("Object %s does not exist: %v", objName, err))
		return false
	}
	return true
}

func (s3 *S3) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var keys []string
	
	// Use the parent context to respect cancellation
	listCtx, cancel := context.WithTimeout(ctx, 60*time.Second) // Longer timeout for listing
	defer cancel()
	
	// Construct the full prefix by combining the storage prefix and the requested prefix
	fullPrefix := s3.objName(prefix)
	s3.Logger.Info(fmt.Sprintf("List: prefix=%s, recursive=%v", fullPrefix, recursive))
	
	// Use pagination to avoid loading all objects into memory at once
	objectCh := s3.Client.ListObjects(listCtx, s3.Bucket, minio.ListObjectsOptions{
		Prefix:    fullPrefix,
		Recursive: recursive,
	})
	
	// Process objects in batches
	for obj := range objectCh {
		if obj.Err != nil {
			return nil, fmt.Errorf("error listing objects with prefix %s: %w", fullPrefix, obj.Err)
		}
		
		// Extract the key by removing the storage prefix
		// This ensures we return keys in the format expected by certmagic
		storagePrefix := s3.objName("")
		key := strings.TrimPrefix(obj.Key, storagePrefix)
		
		// Skip lock files
		if strings.HasSuffix(key, ".lock") {
			continue
		}
		
		// Remove leading slash if present
		key = strings.TrimPrefix(key, "/")
		
		keys = append(keys, key)
	}
	
	s3.Logger.Debug(fmt.Sprintf("List found %d objects with prefix %s", len(keys), fullPrefix))
	return keys, nil
}

func (s3 *S3) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	objName := s3.objName(key)
	s3.Logger.Info(fmt.Sprintf("Stat: %v", objName))
	var ki certmagic.KeyInfo
	
	// Use the parent context to respect cancellation
	statCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	oi, err := s3.Client.StatObject(statCtx, s3.Bucket, objName, minio.StatObjectOptions{})
	if err != nil {
		// Check for specific error types
		if strings.Contains(err.Error(), "The specified key does not exist") ||
		   minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return ki, fs.ErrNotExist
		}
		return ki, fmt.Errorf("failed to stat object %s: %w", objName, err)
	}
	
	ki.Key = key
	ki.Size = oi.Size
	ki.Modified = oi.LastModified
	ki.IsTerminal = true
	return ki, nil
}

func (s3 *S3) objName(key string) string {
	return fmt.Sprintf("%s/%s", strings.TrimPrefix(s3.Prefix, "/"), strings.TrimPrefix(key, "/"))
}

func (s3 *S3) objLockName(key string) string {
	return s3.objName(key) + ".lock"
}

// CertMagicStorage converts s to a certmagic.Storage instance.
func (s3 *S3) CertMagicStorage() (certmagic.Storage, error) {
	return s3, nil
}

func (s3 *S3) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		key := d.Val()
		var value string

		if !d.Args(&value) {
			continue
		}

		switch key {
		case "host":
			s3.Host = value
		case "bucket":
			s3.Bucket = value
		case "access_key":
			s3.AccessKey = value
		case "secret_key":
			s3.SecretKey = value
		case "prefix":
			if value != "" {
				s3.Prefix = value
			} else {
				s3.Prefix = "acme"
			}
		case "encryption_key":
			// Store encryption key as bytes
			s3.EncryptionKey = []byte(value)
		case "region":
			s3.Region = value
		case "secure":
			if value == "false" || value == "0" || value == "no" {
				s3.Secure = false
			} else {
				s3.Secure = true
			}
		case "endpoint":
			s3.Endpoint = value
		}
	}
	return nil
}

var (
	_ caddy.Provisioner      = (*S3)(nil)
	_ caddy.StorageConverter = (*S3)(nil)
	_ caddyfile.Unmarshaler  = (*S3)(nil)
)
