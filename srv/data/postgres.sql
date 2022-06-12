create table customers (id SERIAL PRIMARY KEY, shadytel_customer_id int, beerocracy_id int, name text, created_at 
timestamp not null, last_updated timestamp);

create table accounts (id SERIAL PRIMARY KEY, points numeric(8,2) not null, customer_id int not null, created_at 
timestamp not null, last_updated timestamp, partner bool not null, admin bool not null, special bool not null);

create type card_status as enum ('unallocated', 'issued', 'activated', 'blocked', 'lost', 'stolen');

create table cards (pan varchar(19) NOT NULL PRIMARY KEY, account_id integer, name varchar(80), expire timestamp, 
dd1 varchar(31), dd2 numeric(31), status card_status);

create type secrets_type as enum ('pin', 'password', 'totp', 'webauthn');

create table secrets (int serial primary key, account_id int, type secrets_type, secret text, created_at timestamp 
not null, last_used timestamp);

create table sessions (id serial primary key, account_id integer not null, token text not null, created_at 
timestamp not null, last_used timestamp not null);

create type trans_type as enum ('credit_points', 'purchase', 'refund');

create table transactions (id serial primary key, timestamp timestamp, debit_account integer, credit_account 
integer, amount numeric(8,2), auth_code varchar(6), type trans_type, related_transaction int, description text); 

create table authorizations (id serial primary key, pan varchar(19) not null, auth_code varchar(6) not null, 
debit_account int, credit_account int, authorized_debit_amount numeric(8,2), timestamp timestamp, expires 
timestamp);

