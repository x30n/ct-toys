package models

import (
	"crypto/x509"
	"strings"
)

func (db *DB) CachedCertificateCreate(cert *x509.Certificate, x509DbId int64) (int64, error) {
	var id int64

	err := db.QueryRow("INSERT INTO watched_certificate_cache (version, serial_num, not_before, not_after, issuer, subject_common_name, subject_country, subject_state, subject_location, subject_organization, subject_organization_unit, certificate_log_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id", cert.Version, cert.SerialNumber.Int64(), cert.NotBefore, cert.NotAfter, cert.Issuer.CommonName, cert.Subject.CommonName, strings.Join(cert.Subject.Country, ","), strings.Join(cert.Subject.Province, ","), strings.Join(cert.Subject.Locality, ","), strings.Join(cert.Subject.Organization, ","), strings.Join(cert.Subject.OrganizationalUnit, ","), x509DbId).Scan(&id)
	if err != nil {
		return 0, err
	}
	// id, err := result.LastInsertId()
	// if err != nil {
	// return 0, err
	// }
	return id, nil
}
