insert into accounts (name, special) values ('Shadybucks Awarded', true);
insert into accounts (name, partner) values ('Shadytel', true);
insert into accounts (name, partner) values ('Beerocracy', true);


insert into customers (name) values ('Test Customer');
insert into accounts (customer_id, name) values(1, 'Test Account');
insert into secrets (account_id, type, secret) values (4, 'password', '$argon2id$v=19$m=65536,t=3,p=4$PCcEAMAYY8y5F4IQgpCSEg$l+XnddAbLI5EPOc6/ass46CUJGUtv2PTmnsoLrOI0bM');
insert into cards values('8997986672299995',  4, 'CARD/TEST', '2408', 'ABCDEF', '123456', 'activated');

insert into customers (name) values ('supersat');
insert into accounts (customer_id, name, admin) values(2, 'supersat', true);
insert into secrets (account_id, type, secret) values (5, 'password', '$argon2id$v=19$m=65536,t=3,p=4$PCcEAMAYY8y5F4IQgpCSEg$l+XnddAbLI5EPOc6/ass46CUJGUtv2PTmnsoLrOI0bM');
insert into cards values('8997986672200696',  5, 'SAT/SUPER', '2408', 'RSTLNE', '098105', 'activated');
