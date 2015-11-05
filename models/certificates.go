package models

func (db *DB) CertificateCreate(cert []byte) (int64, error) {
	var id int64
	err := db.QueryRow("INSERT INTO certificate_log (x509cert) VALUES($1) RETURNING id", cert).Scan(&id)
	if err != nil {
		return 0, err
	}
	// id, err := result.LastInsertId()
	// if err != nil {
	// return 0, err
	// }
	return id, nil
}
