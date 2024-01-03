package com.example.springsecurity03.controller;


import com.example.springsecurity03.Jpa.Account;
import com.example.springsecurity03.Jpa.AccountDto;
import com.example.springsecurity03.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
@Slf4j
public class HomeController {

	private final UserService service;
	private final PasswordEncoder encoder;

	
	@GetMapping("/home")
	public String home(){
		return "homes";
	}
	@PostMapping("/join")
	@ResponseBody
	public String join(@RequestBody AccountDto dto){
		ModelMapper modelMapper = new ModelMapper();

		Account map = modelMapper.map(dto, Account.class);
		map.setPassword(encoder.encode(map.getPassword()));

		map.setRole("ROLE_USER");
		service.createUser(map);
		return "Ok";
	}
	@GetMapping("/mypage")
	@ResponseBody
	public String myPage(){
		return "UserTestOk";
	}
	@ResponseBody
	@GetMapping("/admin")
	public String adimn(){
		return "admin";
	}
	@ResponseBody
	@GetMapping("/user/test")
	public String userTest(Authentication authentication){
		UserDetails principal = (UserDetails) authentication.getPrincipal();
		log.info("유저 네임 = {}",principal.getUsername());
		return "UserTest";
	}
	@ResponseBody
	@GetMapping("/test")
	public String test(){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String name = authentication.getName();
		log.info("네임 이름 ={}",name);
		return "ok";
	}
	@ResponseBody
	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if(authentication != null){
			new SecurityContextLogoutHandler().logout(request,response,authentication);
		}
		return "ok";
	}


}
