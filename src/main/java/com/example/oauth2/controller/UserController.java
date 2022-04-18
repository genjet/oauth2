package com.example.oauth2.controller;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
	@GetMapping("/user")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
    public Principal user(Principal principal){
        return principal;
    }
}
