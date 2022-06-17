create table customers (id SERIAL PRIMARY KEY, shadytel_customer_id int, beerocracy_id int, name text, created_at 
timestamp not null default NOW(), last_updated timestamp);

create table accounts (id SERIAL PRIMARY KEY, balance numeric(8,2) not null default 0.00, customer_id int not null, created_at 
timestamp not null default NOW(), last_updated timestamp, partner bool not null default false, admin bool not null default false,
special bool not null default false);

create type card_status as enum ('unallocated', 'issued', 'activated', 'blocked', 'lost', 'stolen');

create table cards (pan varchar(19) NOT NULL PRIMARY KEY, account_id integer, name varchar(80), expire timestamp, 
dd1 varchar(31), dd2 numeric(31), status card_status);

create type secrets_type as enum ('pin', 'password', 'totp', 'webauthn');

create table secrets (id serial primary key, account_id int, type secrets_type, secret text, created_at timestamp 
not null default NOW(), last_used timestamp);

create type trans_type as enum ('credit_points', 'purchase', 'refund');

create table transactions (id serial primary key, timestamp timestamp not null default NOW(), debit_account integer not null, credit_account 
integer not null, amount numeric(8,2) not null, pan varchar(19), auth_code varchar(6), type trans_type not null, related_transaction int, description text); 

create table authorizations (id serial primary key, pan varchar(19) not null, auth_code varchar(6) not null, 
debit_account int, credit_account int, authorized_debit_amount numeric(8,2), timestamp timestamp not null default NOW(), 
expires timestamp);

