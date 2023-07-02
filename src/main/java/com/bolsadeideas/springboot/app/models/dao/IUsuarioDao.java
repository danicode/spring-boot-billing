package com.bolsadeideas.springboot.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.bolsadeideas.springboot.app.models.entity.Usuario;

public interface IUsuarioDao extends CrudRepository<Usuario, Long> {

	// por medio del nombre del metodo (query method name), se ejecutara la consulta jpql
	// select u from Usuario u where u.username=?1
	
	//Otra forma con anotacion query ponemos el nombre que querramos y con anotacion query
	// @Query("select u from Usuario u where u.username=?1")
	public Usuario findByUsername(String username);
}
