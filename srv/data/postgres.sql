create table customers (id SERIAL PRIMARY KEY, shadytel_customer_id int, beerocracy_id int, name varchar(80), created_at 
timestamp not null default NOW(), last_updated timestamp);

create table accounts (id SERIAL PRIMARY KEY, name varchar(80), balance numeric(8,2) not null default 0.00, 
available numeric(8,2) not null default 0.00, customer_id int, created_at  timestamp not null default NOW(),
last_updated timestamp, partner bool not null default false, admin bool not null default false,
special bool not null default false, constraint fk_customer_id foreign key(customer_id) references customers(id));

create type card_status as enum ('unallocated', 'issued', 'activated', 'blocked', 'lost', 'stolen');

create table cards (pan varchar(19) NOT NULL PRIMARY KEY, account_id integer, name varchar(80), expires char(4) not null, 
dd1 varchar(31), dd2 numeric(31), status card_status, constraint fk_account_id foreign key (account_id) references accounts(id));

create type secrets_type as enum ('pin', 'password', 'totp', 'webauthn');

create table secrets (id serial primary key, account_id int, type secrets_type, secret text, created_at timestamp 
not null default NOW(), last_used timestamp, constraint fk_account_id foreign key (account_id) references accounts(id));

create type trans_type as enum ('credit_points', 'purchase', 'refund');

create table transactions (id serial primary key, timestamp timestamp not null default NOW(), debit_account integer not null, credit_account 
integer not null, amount numeric(8,2) not null, pan varchar(19), auth_code varchar(6), type trans_type not null, related_transaction int,
description text, constraint fk_debit_aid foreign key (debit_account) references accounts(id),
constraint fk_credit_aid foreign key (credit_account) references accounts(id));

create type auth_status as enum ('pending', 'posted', 'reversed', 'voided', 'expired');

create table authorizations (id serial primary key, pan varchar(19) not null, auth_code varchar(6) not null, 
debit_account int, credit_account int, authorized_debit_amount numeric(8,2), timestamp timestamp not null default NOW(), 
expires timestamp default NOW() + INTERVAL '24 hours', status auth_status not null default 'pending',
constraint fk_debit_aid foreign key (debit_account) references accounts(id),
constraint fk_credit_aid foreign key (credit_account) references accounts(id),
unique(credit_account, auth_code));

