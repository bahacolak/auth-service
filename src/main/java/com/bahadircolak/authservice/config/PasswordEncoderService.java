//package com.bahadircolak.authservice.config;
//
//import org.springframework.stereotype.Service;
//
//import javax.crypto.SecretKeyFactory;
//import javax.crypto.spec.PBEKeySpec;
//import java.security.NoSuchAlgorithmException;
//import java.security.SecureRandom;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.KeySpec;
//import java.util.Base64;
//
//@Service
//public class PasswordEncoderService {
//
//    public String hash(String data, String salt) {
//        byte[] hashedValue = null;
//
//        KeySpec spec = new PBEKeySpec(data.toCharArray(), salt.getBytes(), 5000, 128);
//        try {
//            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
//            hashedValue = factory.generateSecret(spec).getEncoded();
//        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
//            System.out.println(e.getMessage());
//        }
//
//        return Base64.getEncoder().encodeToString(hashedValue);
//    }
//
//    public String generateSalt() {
//        SecureRandom random = new SecureRandom();
//        byte[] salt = new byte[16];
//        random.nextBytes(salt);
//        return Base64.getEncoder().encodeToString(salt);
//    }
//}
