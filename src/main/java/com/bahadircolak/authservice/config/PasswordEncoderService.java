package com.bahadircolak.authservice.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

@Service
public class PasswordEncoderService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public PasswordEncoderService() {
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder();
    }

    public String hash(String data, String salt) {
        String saltedPassword = data + salt;
        return bCryptPasswordEncoder.encode(saltedPassword);
    }

    public String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
}
