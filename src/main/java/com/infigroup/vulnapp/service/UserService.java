package com.infigroup.vulnapp.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.infigroup.vulnapp.repository.UserRepository;

/**
 * Forwards tainted request parameters from the controllers into the repository
 * SQL sinks, completing the cross-file taint flow:
 * UserController -> UserService -> UserRepository.
 */
@Service
public class UserService {

    private final UserRepository repository;

    public UserService(UserRepository repository) {
        this.repository = repository;
    }

    public List<String> search(String name) {
        // Tainted 'name' passed straight through to the SQL sink.
        return repository.searchByName(name);
    }

    public String email(String id) {
        return repository.findEmailById(id);
    }

    public List<String> searchSafe(String name) {
        return repository.searchByNameSafe(name);
    }
}
