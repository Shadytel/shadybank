create table if not exists account
(
  pan text unique not null,
  name text,
  expire int,
  secret text,
  dd1 text,
  dd2 text,
  blocked text,
  track1 text,
  track2 text,
  postal text,
  etc_json text
);

create table if not exists transfer
(
  debit text not null,
  credit text not null,
  amount int not null,
  timestamp int not null,
  note text,
  etc_json text
);

insert into account (pan, name, secret)
values ('8997986672200001', 'root', '1234');
