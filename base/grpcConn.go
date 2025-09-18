package base

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/couchbase/goprotostellar/genproto/internal_xdcr_v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GrpcCredentials implements gRPC PerRPCCredentials interface using basic authentication.
type GrpcCredentials struct {
	// Base64EncodedAuth contains the base64-encoded "username:password" string for gRPC authentication
	Base64EncodedAuth string
	// RequireTLS when set to true ensures the credentials are sent across only on a connection that is TLS/SSL secured
	RequireTLS bool
}

func NewGrpcCredentials(clientCreds Credentials, requireTLS bool) (*GrpcCredentials, error) {
	if len(clientCreds.ClientCertificate_) > 0 {
		// In mTLS mode, PerRPCCredentials are not required.
		// The grpc framework on server side(CNG) automatically extracts the client certificate
		// from the underlying established TLS session and makes it available in the RPC context.
		// Therefore, the certificate does not need to be attached to each outgoing RPC.
		return nil, nil
	}

	// For non-mTLS, username and password must be provided
	if clientCreds.UserName_ == "" || clientCreds.Password_ == "" {
		return nil, errors.New("username and password must not be empty")
	}

	basicAuth := fmt.Sprintf("%s%s%s", clientCreds.UserName_, JsonDelimiter, clientCreds.Password_)
	base64EncodedAuth := base64.StdEncoding.EncodeToString([]byte(basicAuth))

	return &GrpcCredentials{
		Base64EncodedAuth: base64EncodedAuth,
		RequireTLS:        requireTLS,
	}, nil
}

// GetRequestMetadata attaches authentication headers to outgoing RPCs.
func (grpc *GrpcCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		AuthorizationKey: BasicAuthorizationKey + grpc.Base64EncodedAuth,
	}, nil
}

// RequireTransportSecurity reports whether the credentials require a secure
// transport channel (TLS). It returns true if the credentials must be
// transmitted only over TLS, and false if they can be sent over an insecure
// connection.
func (grpc *GrpcCredentials) RequireTransportSecurity() bool {
	return grpc.RequireTLS
}

// TLSConfigOptions holds options for configuring TLS.
type TLSConfigOptions struct {
	// ServerName specifies the hostname for TLS handshake verification.
	ServerName string
	// Creds holds the user credentials for authentication.
	Creds Credentials
	// CACert contains the CA certificate for server certificate verification.
	CACert []byte
	// IsCapella indicates whether the connection string targets a Capella hostname.
	IsCapella bool
	// Insecure, when true, skips server certificate and hostname validation.
	// To be used only in dev or local envs.
	Insecure bool
}

// configureTLS creates a TLS configuration based on the provided options.
func configureTLS(opts TLSConfigOptions) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.Insecure,
	}

	if !opts.Insecure {
		tlsConfig.ServerName = opts.ServerName

		certPool, err := configureCACertPool(opts.CACert, opts.IsCapella)
		if err != nil {
			return nil, fmt.Errorf("failed to configure CA certificate pool: %w", err)
		}
		if certPool != nil {
			tlsConfig.RootCAs = certPool
		}

		// mTLS: attach client cert/key if provided
		// CNG currently does not support mtls
		// Tracking ticket - https://jira.issues.couchbase.com/browse/ING-662
		if len(opts.Creds.ClientCertificate_) > 0 && len(opts.Creds.ClientKey_) > 0 {
			cert, tlsErr := tls.X509KeyPair(opts.Creds.ClientCertificate_, opts.Creds.ClientKey_)
			if tlsErr != nil {
				return nil, fmt.Errorf("failed to load client certificate/key pair: %w", tlsErr)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	return tlsConfig, nil
}

// configureCACertPool creates a certificate pool for server cert verification.
// For Capella, we can rely on the system's default trust store unless a CA certificate is provided explicitly.
// For non-Capella, a valid CA certificate is required.
func configureCACertPool(caCert []byte, isCapella bool) (*x509.CertPool, error) {
	if isCapella && len(caCert) == 0 {
		// Use the system's trust store to validate the server cert.
		return nil, nil
	}

	if len(caCert) == 0 {
		// caCert is required in non-capella deployments
		return nil, errors.New("CA certificate is required for non-Capella deployments")
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to parse CA certificate")
	}
	return certPool, nil
}

func NewXdcrGrpcClient(connStr string, creds Credentials, authMech HttpAuthMech, caCert []byte) (internal_xdcr_v1.XdcrServiceClient, error) {
	isSecure := authMech == HttpAuthMechHttps

	// Configure per-RPC credentials.
	perRpcCreds, err := NewGrpcCredentials(creds, isSecure)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC credentials: %w", err)
	}

	// Configure TLS.
	tlsOpts := TLSConfigOptions{
		ServerName: GetHostName(connStr),
		CACert:     caCert,
		Creds:      creds,
		IsCapella:  strings.Contains(connStr, CapellaHostnameSuffix),
		Insecure:   !isSecure,
	}
	tlsConfig, err := configureTLS(tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}

	// Set up gRPC dial options.
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithUserAgent(GoxdcrUserAgent + GoxdcrCngUserAgentSuffix),
	}
	if perRpcCreds != nil {
		dialOptions = append(dialOptions, grpc.WithPerRPCCredentials(perRpcCreds))
	}

	// Establish the gRPC connection.
	grpcConn, err := grpc.NewClient(connStr, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to establish gRPC connection: %v", err)
	}

	return internal_xdcr_v1.NewXdcrServiceClient(grpcConn), nil
}
