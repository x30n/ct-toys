package models

import (
	"crypto/x509"
	"database/sql"

	_ "github.com/lib/pq"
)

type Datastore interface {
	// CT Log Sources
	LogSourceCreateOrUpdate(LogSource) (int64, error)
	LogSourceCreate(LogSource) (int64, error)
	LogSourceUpdateLastSeen(int64, int64) error

	AllLogs() ([]*LogSource, error)

	// Raw (x509) Certificates
	CertificateCreate([]byte) (int64, error)

	// Cached (Watched) Certificates
	CachedCertificateCreate(*x509.Certificate, int64) (int64, error)

	// SANs
	// SANCreate(string, int64) (int64, error)
}

type DB struct {
	*sql.DB
}

func NewDB(dataSourceName string) (*DB, error) {
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}
