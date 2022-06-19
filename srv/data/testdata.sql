insert into customers (name) values ('Test Customer');
insert into accounts (customer_id, name) values(1, 'Test Account');
insert into secrets (account_id, type, secret) values (1, 'password', '$argon2id$v=19$m=65536,t=3,p=4$PCcEAMAYY8y5F4IQgpCSEg$l+XnddAbLI5EPOc6/ass46CUJGUtv2PTmnsoLrOI0bM');
insert into cards values('8997986672299995',  1, 'CARD/TEST', '2408', 'ABCDEF', '123456', 'activated');
