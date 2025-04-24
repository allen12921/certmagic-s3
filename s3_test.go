package s3

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"
)

// Mock S3 client for testing
type mockS3Client struct {
	objects map[string][]byte
	err     error
}

func (m *mockS3Client) PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	if m.err != nil {
		return minio.UploadInfo{}, m.err
	}
	
	if m.objects == nil {
		m.objects = make(map[string][]byte)
	}
	
	data, err := io.ReadAll(reader)
	if err != nil {
		return minio.UploadInfo{}, err
	}
	
	m.objects[objectName] = data
	return minio.UploadInfo{
		Key:  objectName,
		Size: int64(len(data)),
	}, nil
}

func (m *mockS3Client) GetObject(ctx context.Context, bucketName, objectName string, opts minio.GetObjectOptions) (*minio.Object, error) {
	if m.err != nil {
		return nil, m.err
	}
	
	data, exists := m.objects[objectName]
	if !exists {
		return nil, minio.ErrorResponse{
			Code: "NoSuchKey",
		}
	}
	
	return &minio.Object{
		ObjectInfo: minio.ObjectInfo{
			Key:          objectName,
			Size:         int64(len(data)),
			LastModified: time.Now(),
		},
	}, nil
}

func (m *mockS3Client) RemoveObject(ctx context.Context, bucketName, objectName string, opts minio.RemoveObjectOptions) error {
	if m.err != nil {
		return m.err
	}
	
	if m.objects == nil {
		return nil
	}
	
	delete(m.objects, objectName)
	return nil
}

func (m *mockS3Client) StatObject(ctx context.Context, bucketName, objectName string, opts minio.StatObjectOptions) (minio.ObjectInfo, error) {
	if m.err != nil {
		return minio.ObjectInfo{}, m.err
	}
	
	data, exists := m.objects[objectName]
	if !exists {
		return minio.ObjectInfo{}, minio.ErrorResponse{
			Code: "NoSuchKey",
		}
	}
	
	return minio.ObjectInfo{
		Key:          objectName,
		Size:         int64(len(data)),
		LastModified: time.Now(),
	}, nil
}

func (m *mockS3Client) ListObjects(ctx context.Context, bucketName string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo {
	ch := make(chan minio.ObjectInfo)
	
	go func() {
		defer close(ch)
		
		if m.err != nil {
			return
		}
		
		for key, data := range m.objects {
			if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
				continue
			}
			
			ch <- minio.ObjectInfo{
				Key:          key,
				Size:         int64(len(data)),
				LastModified: time.Now(),
			}
		}
	}()
	
	return ch
}

func (m *mockS3Client) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return true, nil
}

func TestS3Storage(t *testing.T) {
	// Create a mock S3 client
	mockClient := &mockS3Client{
		objects: make(map[string][]byte),
	}
	
	// Create a logger
	logger, _ := zap.NewDevelopment()
	
	// Create an S3 storage instance
	s3Storage := &S3{
		Logger:    logger,
		Client:    mockClient,
		Bucket:    "test-bucket",
		Prefix:    "test-prefix",
		iowrap:    &CleartextIO{},
	}
	
	// Test Store and Load
	ctx := context.Background()
	testKey := "test-key"
	testData := []byte("test-data")
	
	err := s3Storage.Store(ctx, testKey, testData)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	
	data, err := s3Storage.Load(ctx, testKey)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	
	if string(data) != string(testData) {
		t.Errorf("Load data mismatch, got: %s, want: %s", data, testData)
	}
	
	// Test Exists
	exists := s3Storage.Exists(ctx, testKey)
	if !exists {
		t.Errorf("Exists returned false for existing key")
	}
	
	exists = s3Storage.Exists(ctx, "non-existent-key")
	if exists {
		t.Errorf("Exists returned true for non-existent key")
	}
	
	// Test Delete
	err = s3Storage.Delete(ctx, testKey)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	
	exists = s3Storage.Exists(ctx, testKey)
	if exists {
		t.Errorf("Key still exists after deletion")
	}
	
	// Test List
	// Store multiple keys
	keys := []string{"key1", "key2", "key3"}
	for _, key := range keys {
		err := s3Storage.Store(ctx, key, []byte("data-"+key))
		if err != nil {
			t.Fatalf("Store failed for key %s: %v", key, err)
		}
	}
	
	// Also store a lock file that should be ignored
	err = s3Storage.Store(ctx, "key4.lock", []byte("lock-data"))
	if err != nil {
		t.Fatalf("Store failed for lock file: %v", err)
	}
	
	// List all keys
	listedKeys, err := s3Storage.List(ctx, "", true)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	
	if len(listedKeys) != len(keys) {
		t.Errorf("List returned wrong number of keys, got: %d, want: %d", len(listedKeys), len(keys))
	}
	
	// Check that lock file was ignored
	for _, key := range listedKeys {
		if strings.HasSuffix(key, ".lock") {
			t.Errorf("List included lock file: %s", key)
		}
	}
	
	// Test Stat
	for _, key := range keys {
		info, err := s3Storage.Stat(ctx, key)
		if err != nil {
			t.Fatalf("Stat failed for key %s: %v", key, err)
		}
		
		if info.Key != key {
			t.Errorf("Stat returned wrong key, got: %s, want: %s", info.Key, key)
		}
		
		if !info.IsTerminal {
			t.Errorf("Stat returned non-terminal key")
		}
	}
	
	// Test Lock and Unlock
	err = s3Storage.Lock(ctx, "lock-key")
	if err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	
	// Verify lock file exists
	exists = s3Storage.Exists(ctx, "lock-key.lock")
	if !exists {
		t.Errorf("Lock file does not exist after Lock")
	}
	
	err = s3Storage.Unlock(ctx, "lock-key")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	
	// Verify lock file was removed
	exists = s3Storage.Exists(ctx, "lock-key.lock")
	if exists {
		t.Errorf("Lock file still exists after Unlock")
	}
}

func TestS3Integration(t *testing.T) {
	// Skip integration tests unless explicitly enabled
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration tests. Set RUN_INTEGRATION_TESTS=true to run")
	}
	
	// Create a real S3 client for integration testing
	client, err := minio.New("play.min.io", &minio.Options{
		Creds:  credentials.NewStaticV4("Q3AM3UQ867SPQQA43P2F", "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG", ""),
		Secure: true,
	})
	
	if err != nil {
		t.Fatalf("Failed to create minio client: %v", err)
	}
	
	// Create a logger
	logger, _ := zap.NewDevelopment()
	
	// Create an S3 storage instance
	s3Storage := &S3{
		Logger:    logger,
		Client:    client,
		Bucket:    "certmagic-test",
		Prefix:    "test-" + time.Now().Format("20060102-150405"),
		iowrap:    &CleartextIO{},
	}
	
	// Create test bucket if it doesn't exist
	ctx := context.Background()
	exists, err := client.BucketExists(ctx, s3Storage.Bucket)
	if err != nil {
		t.Fatalf("Failed to check if bucket exists: %v", err)
	}
	
	if !exists {
		err = client.MakeBucket(ctx, s3Storage.Bucket, minio.MakeBucketOptions{})
		if err != nil {
			t.Fatalf("Failed to create bucket: %v", err)
		}
	}
	
	// Run basic storage tests
	testKey := "integration-test-key"
	testData := []byte("integration-test-data")
	
	err = s3Storage.Store(ctx, testKey, testData)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	
	data, err := s3Storage.Load(ctx, testKey)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	
	if string(data) != string(testData) {
		t.Errorf("Load data mismatch, got: %s, want: %s", data, testData)
	}
	
	// Clean up
	err = s3Storage.Delete(ctx, testKey)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

func TestS3StorageImplementsCertMagicStorage(t *testing.T) {
	var _ certmagic.Storage = (*S3)(nil)
}
