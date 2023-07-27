/* Populate tables */

/* Populate tables regiones */
INSERT INTO regiones (id, nombre) VALUES (1, 'Sudamérica');
INSERT INTO regiones (id, nombre) VALUES (2, 'Centroamérica');
INSERT INTO regiones (id, nombre) VALUES (3, 'Norteamérica');
INSERT INTO regiones (id, nombre) VALUES (4, 'Europa');
INSERT INTO regiones (id, nombre) VALUES (5, 'Asia');
INSERT INTO regiones (id, nombre) VALUES (6, 'Africa');
INSERT INTO regiones (id, nombre) VALUES (7, 'Oceanía');
INSERT INTO regiones (id, nombre) VALUES (8, 'Antártida');

/* Populate tabla clientes */
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(1, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-01', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(1, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-02', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(2, 'Linus', 'Torvalds', 'linus.torvalds@gmail.com', '2017-08-03', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(2, 'Jane', 'Doe', 'jane.doe@gmail.com', '2017-08-04', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(4, 'Rasmus', 'Lerdorf', 'rasmus.lerdorf@gmail.com', '2017-08-05', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(4, 'Erich', 'Gamma', 'erich.gamma@gmail.com', '2017-08-06', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(4, 'Richard', 'Helm', 'richard.helm@gmail.com', '2017-08-07', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(3, 'Ralph', 'Johnson', 'ralph.johnson@gmail.com', '2017-08-08', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(3, 'John', 'Vlissides', 'john.vlissides@gmail.com', '2017-08-09', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(3, 'James', 'Gosling', 'james.gosling@gmail.com', '2017-08-010', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(3, 'Bruce', 'Lee', 'bruce.lee@gmail.com', '2017-08-11', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(5, 'Johnny', 'Doe', 'johnny.doe@gmail.com', '2017-08-12', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(5, 'John', 'Roe', 'john.roe@gmail.com', '2017-08-13', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(6, 'Jane', 'Roe', 'jane.roe@gmail.com', '2017-08-14', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(6, 'Richard', 'Doe', 'richard.doe@gmail.com', '2017-08-15', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(6, 'Janie', 'Doe', 'janie.doe@gmail.com', '2017-08-16', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(7, 'Phillip', 'Webb', 'phillip.webb@gmail.com', '2017-08-17', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(7, 'Stephane', 'Nicoll', 'stephane.nicoll@gmail.com', '2017-08-18', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(7, 'Sam', 'Brannen', 'sam.brannen@gmail.com', '2017-08-19', '');  
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(7, 'Juergen', 'Hoeller', 'juergen.Hoeller@gmail.com', '2017-08-20', ''); 
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(8, 'Janie', 'Roe', 'janie.roe@gmail.com', '2017-08-21', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(8, 'John', 'Smith', 'john.smith@gmail.com', '2017-08-22', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(8, 'Joe', 'Bloggs', 'joe.bloggs@gmail.com', '2017-08-23', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(8, 'John', 'Stiles', 'john.stiles@gmail.com', '2017-08-24', '');
INSERT INTO clientes (region_id, nombre, apellido, email, create_at, foto) VALUES(8, 'Richard', 'Roe', 'stiles.roe@gmail.com', '2017-08-25', '');

/* Populate tabla productos */
INSERT INTO productos (nombre, precio, create_at) VALUES('Panasonic Pantalla LCD', 259990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES('Sony Camara digital DSC-W320B', 123490, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES('Apple iPod shuffle', 1499990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES('Sony Notebook Z110', 37990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES('Hewlett Packard Multifuncional F2280', 69990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES('Bianchi Bicicleta Aro 26', 69990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES('Mica Comoda 5 Cajones', 299990, NOW());

/* Creamos algunas facturas */
INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES('Factura equipos de oficina', null, 1, NOW());
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(1, 1, 1);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(2, 1, 4);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(1, 1, 5);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(1, 1, 7);

INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES('Factura Bicicleta', 'Alguna nota importante!', 1, NOW());
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(3, 2, 6);

/* Creamos algunos usuarios con sus roles */
INSERT INTO users (username, password, enabled) VALUES('danicode', '$2a$10$ZJQ9tZPBGM6u3bKLEUgLReVX5.iNwNaVmNlB/CmUjQjEBBJbtKSxu', 1);
INSERT INTO users (username, password, enabled) VALUES('admin', '$2a$10$hUIiVjNI8CAyNRm7q9nDreX/mAZg7QO4uEcSxSVXT5TmZ.mg63ME2', 1);

INSERT INTO authorities (user_id, authority) VALUES(1, 'ROLE_USER');
INSERT INTO authorities (user_id, authority) VALUES(2, 'ROLE_USER');
INSERT INTO authorities (user_id, authority) VALUES(2, 'ROLE_ADMIN');
