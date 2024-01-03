package com.example.springsecurity03.Service;

import com.example.springsecurity03.Jpa.Account;
import com.example.springsecurity03.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;
    public void createUser(Account account){
        repository.save(account);
    }
}
