# Certmagic Storage Backend for S3

This library allows you to use any S3-compatible provider as key/certificate storage backend for your [Certmagic](https://github.com/caddyserver/certmagic)-enabled HTTPS server. To protect your keys from unwanted attention, client-side encryption using [secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox?tab=doc) is possible.

## What is a S3-compatible service?

In the current state, any service must support the following:

- v4 Signatures
- HTTPS
- A few basic operations:
	- Bucket Exists
	- Get Object
	- Put Object
	- Remove Object
	- Stat Object
	- List Objects

Known good providers/software:

- Minio (with HTTPS enabled)
- Backblaze
- OVH
- AWS S3
- DigitalOcean Spaces
- Linode Object Storage

## Usage

### Caddy Server Configuration

Add the following to your Caddyfile:

```
{
  storage s3 {
    host your-s3-host.com
    bucket your-bucket-name
    prefix certmagic  # Optional, defaults to "acme"
    access_key YOUR_ACCESS_KEY
    secret_key YOUR_SECRET_KEY
    region us-east-1  # Optional, for AWS S3
    secure true  # Optional, defaults to true
    endpoint custom-endpoint.com  # Optional, for custom S3 endpoints
    encryption_key YOUR_32_BYTE_ENCRYPTION_KEY  # Optional
  }
}
```

### Go Code Usage

```go
package main

import (
	"github.com/caddyserver/certmagic"
	"github.com/allen12921/certmagic-s3"
)

func main() {
	// Create S3 storage
	storage := &s3.S3{
		Host:      "your-s3-host.com",
		Bucket:    "your-bucket-name",
		Prefix:    "certmagic",  // Optional, defaults to "acme"
		AccessKey: "YOUR_ACCESS_KEY",
		SecretKey: "YOUR_SECRET_KEY",
		Region:    "us-east-1",  // Optional, for AWS S3
		Secure:    true,         // Optional, defaults to true
		Endpoint:  "custom-endpoint.com",  // Optional, for custom S3 endpoints
		EncryptionKey: []byte("32-byte-encryption-key-goes-here"),  // Optional
	}
	
	// Use the storage with certmagic
	certmagic.Default.Storage = storage
	
	// Continue with your certmagic configuration...
}
```

## Features

- Support for any S3-compatible storage provider
- Optional client-side encryption of certificates and keys
- Support for AWS IAM roles and environment variables for credentials
- Configurable HTTPS/HTTP connection
- Support for custom endpoints and regions
- Proper resource management and error handling
- Comprehensive test coverage

## Security Considerations

- Always use HTTPS (secure=true) in production environments
- Use IAM roles or environment variables instead of hardcoded credentials when possible
- Enable encryption for sensitive certificate data
- Ensure your S3 bucket has appropriate access controls

## Credit

This project was forked from [@thomersch](https://github.com/thomersch)'s wonderful [Certmagic Storage Backend for Generic S3 Providers](https://github.com/thomersch/certmagic-generic-s3) repository.

## License

This project is licensed under [Apache 2.0](https://github.com/thomersch/certmagic-generic-s3/issues/1), an open source license.