package com.bolsadeideas.springboot.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.bolsadeideas.springboot.app.models.entity.Cliente;
import com.bolsadeideas.springboot.app.models.entity.Region;

public interface IClienteDao extends CrudRepository<Cliente, Long>  {

	@Query("from Region")
	public List<Region> findAllRegions();
}
