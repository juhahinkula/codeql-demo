package com.example.codeqldemo;

import org.springframework.data.annotation.Id;
import java.time.LocalDateTime;

public class User {
    @Id
    private Long id;
    private String username;
    private String email;
    private LocalDateTime createdDate;

    public User() {
        this.createdDate = LocalDateTime.now();
    }

    public User(String username, String email) {
        this.username = username;
        this.email = email;
        this.createdDate = LocalDateTime.now();
    }

    public Long getId() { return id; }

    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }

    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }

    public void setEmail(String email) { this.email = email; }

    public LocalDateTime getCreatedDate() { return createdDate; }

    public void setCreatedDate(LocalDateTime createdDate) { this.createdDate = createdDate; }
}