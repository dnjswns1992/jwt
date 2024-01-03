package com.example.springsecurity03.controller.login;
import com.example.springsecurity03.Jpa.AccountDto;
import com.example.springsecurity03.Service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class LoginController {

	private final UserService service;



}
