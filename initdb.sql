CREATE TABLE log_source (
id serial NOT NULL,
description varchar(255) NOT NULL,
pubkey varchar(1024) NOT NULL,
url varchar(512) NOT NULL,
max_merge_delay int NOT NULL,
operated_by varchar(255) NOT NULL,
last_seen_id bigint
);

CREATE TABLE certificate_log (
id bigserial NOT NULL,
x509cert bytea NOT NULL
);

CREATE TABLE watched_certificate_cache (
id bigserial NOT NULL,
version int NOT NULL,
serial_num bigint NOT NULL,
not_before timestamp NOT NULL,
not_after timestamp NOT NULL,
issuer text NOT NULL, 
subject_common_name varchar(255) NOT NULL,
subject_country varchar(2) NOT NULL,
subject_state varchar(255) NOT NULL,
subject_location varchar(255) NOT NULL,
subject_organization text NOT NULL,
subject_organization_unit text NOT NULL,
certificate_log_id bigint NOT NULL
);

CREATE TABLE san (
id bigserial NOT NULL,
subject_alternative_name varchar(255) NOT NULL,
certificate_log_id bigint NOT NULL
);

ALTER TABLE log_source ADD PRIMARY KEY (id);
ALTER TABLE certificate_log ADD PRIMARY KEY (id);
ALTER TABLE watched_certificate_cache ADD PRIMARY KEY (id);
ALTER TABLE san ADD PRIMARY KEY (id);
