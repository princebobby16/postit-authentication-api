
-- +goose Up
CREATE SCHEMA postit_auth;

CREATE TABLE IF NOT EXISTS postit_auth.company
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
    namespace character varying (100) NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (company_id)
);

CREATE TABLE IF NOT EXISTS postit_auth.login
(
    login_id uuid NOT NULL REFERENCES postit_auth.company,
    username character varying (200) NOT NULL,
    password character varying (200) NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (login_id)
);

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- +goose StatementBegin
DO $$
DECLARE
    companyId uuid = uuid_generate_v4();
    password character varying(200) = '$2a$10$zYh5q2HvEhiU7Iqa0U9BPeQC6fNTtsXcEbeqvdECR8ppwH4Yp2vxu';
    phoneNumbers character varying(200)[] = array['0505265215'];
BEGIN
    INSERT INTO postit_auth.company
    (
        company_id,
        company_name,
        company_email,
        company_phone_numbers,
        company_ghana_post_address,
        company_address,
        company_website,
        admin_first_name,
        admin_last_name
    ) VALUES
    (
        companyId,
        'PostIt',
        'shiftrgh@gmail.com',
        phoneNumbers,
        'GW-0809-8768',
        'Accra, Ghana',
        'shiftr.herokuapp.com',
        'Prince',
        'Bobby'
    );

    INSERT INTO postit_auth.login(login_id, username, password) VALUES(companyId, 'admin', password);
END $$;
-- +goose StatementEnd
-- SQL in section 'Up' is executed when this migration is applied

-- +goose Down
DROP TABLE IF EXISTS postit_auth.login;
DROP TABLE IF EXISTS postit_auth.company;
DROP SCHEMA IF EXISTS postit_auth CASCADE;
-- SQL section 'Down' is executed when this migration is rolled back
