/**
 * 
 */
package com.awswebservice.domain.prodosUser;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

public interface ProdosUserRepository extends CrudRepository<ProdosUser, Long> {
	
	Optional<ProdosUser> findByUsername(String username);
}
