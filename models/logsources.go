package models

import "database/sql"

type LogSource struct {
	Description   string `json:"description"`
	PubKey        string `json:"key"`
	URL           string `json:"url"`
	MaxMergeDelay int    `json:"maximum_merge_delay"`
	Operator      []int  `json:"operated_by"`
	OperatedBy    string
	LastSeenId    int64
	DBID          int64
}

// // This stub was meant to do the UPSERT in a transaction, but having trouble...
// func (db *DB) LogSourceCreateOrUpdate_broken(log LogSource) (err error) {
// 	tx, err := db.Begin()
// 	if err != nil {
// 		return
// 	}

// 	// stmt, err := tx.Prepare("DO $do$ BEGIN UPDATE log_source SET description = $1, pubkey = $2, max_merge_delay = $3, operated_by = $4 WHERE url = $5;IF NOT FOUND THEN INSERT INTO log_source values ($1, $2, $5, $3, $4); END IF; END $do$")
// 	// if err != nil {
// 	// return
// 	// }
// 	defer func() {
// 		if err != nil {
// 			tx.Rollback()
// 			return
// 		}
// 		err = tx.Commit()
// 	}()
// 	// if _, err = tx.Exec("UPDATE log_source SET description = $1, pubkey = $2, max_merge_delay = $3, operated_by = $4 WHERE url = $5;IF NOT FOUND THEN INSERT INTO log_source values ($1, $2, $5, $3, $4);", log.Description, log.PubKey, log.MaxMergeDelay, log.OperatedBy, log.URL); err != nil {
// 	if _, err = tx.Exec("INSERT INTO log_source (description, pubkey, url, max_merge_delay, operated_by) values ($1, $2, $5, $3, $4)", log.Description, log.PubKey, log.MaxMergeDelay, log.OperatedBy, log.URL); err != nil {
// 		return
// 	}
// 	return
// }

func (db *DB) LogSourceCreateOrUpdate(log LogSource) (int64, error) {
	// Should really be a proper transactional UPSERT, since this vuln
	// to race condition if running concurrently. Low volume for now...
	id, err := db.LogSourceExists(log)
	if err == sql.ErrNoRows {
		id, err = db.LogSourceCreate(log)
		return id, nil
	} else if err != nil {
		return 0, err
	}
	if err := db.LogSourceUpdate(log, id); err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) LogSourceExists(log LogSource) (int64, error) {
	result := db.QueryRow("SELECT id from log_source where url = $1", log.URL)
	var retval int64
	err := result.Scan(&retval)
	if err != nil {
		return 0, err
	}
	return retval, nil
}

func (db *DB) LogSourceUpdate(log LogSource, id int64) error {
	_, err := db.Exec("UPDATE log_source SET description = $1, pubkey = $2, max_merge_delay = $3, operated_by = $4 WHERE id = $5", log.Description, log.PubKey, log.MaxMergeDelay, log.OperatedBy, id)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) LogSourceCreate(log LogSource) (int64, error) {
	result, err := db.Exec("INSERT INTO log_source (description, pubkey, url, max_merge_delay, operated_by, last_seen_id) VALUES($1, $2, $3, $4, $5, 0) RETURNING id", log.Description, log.PubKey, log.URL, log.MaxMergeDelay, log.OperatedBy)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) AllLogs() ([]*LogSource, error) {
	rows, err := db.Query("SELECT id, description, pubkey, url, max_merge_delay, operated_by, last_seen_id FROM log_source")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]*LogSource, 0)
	for rows.Next() {
		log := new(LogSource)
		err := rows.Scan(&log.DBID, &log.Description, &log.PubKey, &log.URL, &log.MaxMergeDelay, &log.OperatedBy, &log.LastSeenId)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return logs, nil
}
