INSERT INTO PRODUCT (id, name, type, brand, desc) values ('MOB01', 'Samsung A6 plus', 'Mobile', 'Samsung', 'Samsung A6 plus is very nice phone with 24mp front camera');
INSERT INTO PRODUCT (id, name, type, brand, desc) values ('MOB02', 'iPhone X plus', 'Mobile', 'Apple', 'iPhone X plus is very nice phone with 24mp front camera');
INSERT INTO PRODUCT (id, name, type, brand, desc) values ('TLV01', 'Sony Bravia KLV-50W662F 50 Inch Full HD', 'Television', 'Sony', 'Sony Bravia is full HD tv');
INSERT INTO PRODUCT (id, name, type, brand, desc) values ('CAM01', 'Canon EOS 1500D Digital SLR Camera', 'DSLR Camera', 'Canon', 'Best DSLR camera in the market');
INSERT INTO PRODUCT (id, name, type, brand, desc) values ('SPK01', 'JBL Cinema 510 5.1 with Powered Subwoofer', 'Home Theater Speaker', 'JBL', 'This sound system is suitable for the Home Theater');

INSERT INTO USER (id, username, password, role) values (100, 'dinesh', '$2a$04$HCZQH4c0VIIz0KxO1Ux.c.REEM.sQZDyA8eZl8A48bBIYIczzSET6', 'USER');
INSERT INTO USER (id, username, password, role) values (101, 'anamika', '$2a$04$HCZQH4c0VIIz0KxO1Ux.c.REEM.sQZDyA8eZl8A48bBIYIczzSET6', 'USER');
INSERT INTO USER (id, username, password, role) values (102, 'arnav', '$2a$04$Y5tgmB9IAsE4yPrA.oghQO9jfD6u4qSviHCbVXww3FXgOTnC4da0a', 'ADMIN');
INSERT INTO USER (id, username, password, role) values (103, 'rushika', '$2a$04$Y5tgmB9IAsE4yPrA.oghQO9jfD6u4qSviHCbVXww3FXgOTnC4da0a', 'ADMIN');


INSERT INTO ACCOUNT (id, email, name, password, picture, role, user_role, user_roles) values (103, '2@3', 'user', '$2a$10$ZZJr1nYeioNPXRiDgHm3/ecgXiUifEqAiPQtnjb2g6g7LYib/zygy', '','', 'ROLE_USER','');
--
-- INSERT INTO ACCOUNT (id, name, password, userRole) values (103, 'user', '$2a$10$ZZJr1nYeioNPXRiDgHm3/ecgXiUifEqAiPQtnjb2g6g7LYib/zygy', 'ROLE_USER');
-- INSERT INTO ACCOUNT (id, name, password, userRole) values (103, 'manager', '$2a$10$ZZJr1nYeioNPXRiDgHm3/ecgXiUifEqAiPQtnjb2g6g7LYib/zygy', 'ROLE_MANAGER');
-- INSERT INTO ACCOUNT (id, name, password, userRole) values (103, 'admin', '$2a$10$ZZJr1nYeioNPXRiDgHm3/ecgXiUifEqAiPQtnjb2g6g7LYib/zygy', 'ROLE_ADMIN');
