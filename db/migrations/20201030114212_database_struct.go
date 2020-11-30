
package main

import (
	"database/sql"
	"github.com/lib/pq"
	"github.com/twinj/uuid"
	"postit-authentication-server/pkg/logs"
)

// Up is executed when this migration is applied
func Up_20201030114212(txn *sql.Tx) {
	logs.Log("==============================================================")
	logs.Log("Running migrations...")
	logs.Log("==============================================================")
	_, err := txn.Exec(`CREATE SCHEMA postit_auth`)
	if err != nil {
		logs.Log("Unable to create schema")
		logs.Log(err)
	}

	_, err = txn.Exec(`CREATE TABLE IF NOT EXISTS postit_auth.company 
		(
			company_id uuid NOT NULL,
			company_name character varying (200) NOT NULL,
			company_email text NOT NULL UNIQUE,
			company_phone_numbers character varying (200)[] NOT NULL, -- At least one
			company_ghana_post_address character varying (200),
			company_address character varying (200) NOT NULL,
			company_website character varying (200),
			admin_first_name character varying (200) NOT NULL,
			admin_last_name character varying (200) NOT NULL,
			created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (company_id)
		)
		WITH (
    		OIDS = FALSE
		);
	
		ALTER TABLE postit_auth.company
    	OWNER to postgres;`)
	if err != nil {
		logs.Log(err)
	}

	_, err = txn.Exec(`CREATE TABLE IF NOT EXISTS postit_auth.login 
		(
			login_id uuid NOT NULL REFERENCES postit_auth.company,
			username character varying (200) NOT NULL,
			password character varying (200) NOT NULL,
			created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (login_id)
		)
		WITH (
    		OIDS = FALSE
		);
	
		ALTER TABLE postit_auth.login
    	OWNER to postgres;`)
	if err != nil {
		logs.Log(err)
	}
	companyId := uuid.NewV4()
	password := "$2a$10$zYh5q2HvEhiU7Iqa0U9BPeQC6fNTtsXcEbeqvdECR8ppwH4Yp2vxu"
	phoneNumbers := []string{"0505265215"}

	_, err = txn.Exec(`INSERT INTO postit_auth.company(company_id, company_name, company_email, company_phone_numbers, company_address, company_website, admin_first_name, admin_last_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
 		&companyId,
 		"PostIt",
 		"shiftrgh@gmail.com",
 		pq.Array(&phoneNumbers),
 		"Adjen Kotoku, Accra, Ghana",
 		"shiftr.herokuapp.com",
 		"Prince",
 		"Bobby",
	)
	if err != nil {
		logs.Log("DATA ERROR: ", err)
	}

	_, err = txn.Exec(`INSERT INTO postit_auth.login(login_id, username, password) VALUES($1, $2, $3)`,
		&companyId,
		"shiftr@shiftr.com",
		&password,
	)
}

// Down is executed when this migration is rolled back
func Down_20201030114212(txn *sql.Tx) {
	_, err := txn.Exec(`DROP TABLE IF EXISTS postit_auth.login, postit_auth.company`)
	if err != nil {
		logs.Log(err)
	}

	_, err = txn.Exec(`DROP SCHEMA postit_auth`)
}
