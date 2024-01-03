package com.example.springsecurity03.Repository;

import com.example.springsecurity03.Jpa.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public interface UserRepository extends JpaRepository<Account,Long> {

    public Account findByUsername(String username);
}
