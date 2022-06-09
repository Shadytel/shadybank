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

-- two entries in this table per transfer
create table if not exists transfer
(
  pan text not null,
  tr_uuid text not null, -- uuid for the transaction pair
  amount int not null,
  timestamp int not null,
  note text,
  etc_json text
);

insert into account (pan, name, secret)
values ('1001', 'root', '1234');

insert into account (pan, name, secret)
values ('1002', 'user', '1234');

insert into transfer (pan, tr_uuid, amount, timestamp, note)
values ('1001', 'fe886fa4-cbe4-4e50-a303-d4b4aa63c143', -100, 1654791940, 'opening deposit');

insert into transfer (pan, tr_uuid, amount, timestamp, note)
values ('1002', 'fe886fa4-cbe4-4e50-a303-d4b4aa63c143', 100, 1654791940, 'welcome to toorcamp');
