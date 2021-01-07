package com.awswebservice.domain.user;



import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
    Account findByName(String username);

    int countByName(String username);

}