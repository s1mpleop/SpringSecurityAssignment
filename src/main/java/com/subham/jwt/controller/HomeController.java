package com.subham.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.Principal;

@RestController
public class HomeController {

    @GetMapping("/")
    public String helloWorld(){
        return "hello world";
    }

    @GetMapping("/hello")
    public String home(Principal principal){
        return "Hello, " + principal.getName();
    }
}
