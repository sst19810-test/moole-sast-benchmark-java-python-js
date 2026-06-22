package com.infigroup.vulnapp.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.infigroup.vulnapp.service.UserService;

/**
 * User endpoints. The @RequestParam values here are the SOURCE of the
 * SQL-injection taint flows that terminate in UserRepository.
 */
@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/search")
    public List<String> search(@RequestParam String name) {
        // SOURCE (CWE-89): name -> UserService.search -> UserRepository.searchByName
        return userService.search(name);
    }

    @GetMapping("/email")
    public String email(@RequestParam String id) {
        // SOURCE (CWE-89): id -> UserService.email -> UserRepository.findEmailById
        return userService.email(id);
    }
}
