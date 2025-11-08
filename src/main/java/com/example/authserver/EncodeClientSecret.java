package com.example.authserver;

import java.util.Base64;

public class EncodeClientSecret {
    public static void main(String[] args) {
        String clientId = "my-client";
        String clientSecret = "my-secret";  // plain secret, not encoded with BCrypt!

        String pair = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(pair.getBytes());

        System.out.println("Authorization header value:");
        System.out.println("Basic " + encodedAuth);}

}
