package com.nazim.authserver.services;

import com.nazim.authserver.entities.RSAKey;
import com.nazim.authserver.repositories.RSAKeyRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class KeyRotationService {

    private static final Logger logger = LoggerFactory.getLogger(KeyRotationService.class);

    private final RSAKeyRepository rsaKeyRepository;

    @PostConstruct
    public void initializeKeys() {
        getOrGenerateActiveKey();  // Ensure that an RSA key is generated when the application starts
    }

    @Transactional
    public RSAKey getOrGenerateActiveKey() {
        return rsaKeyRepository.findByActiveTrue().orElseGet(() -> {
            KeyPair keyPair = generateNewKeyPair();
            RSAKey newKey = new RSAKey();
            newKey.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            newKey.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            newKey.setKeyId(UUID.randomUUID().toString());
            newKey.setActive(true);
            rsaKeyRepository.save(newKey);
            return newKey;
        });
    }

    @Transactional
    @Scheduled(cron = "#{@keyRotationCron}")
    public void rotateKeys() {
        RSAKey currentKey = rsaKeyRepository.findByActiveTrue()
                .orElseThrow(() -> new RuntimeException("No active RSA Key found"));
        currentKey.setActive(false);
        rsaKeyRepository.save(currentKey);

        KeyPair newKeyPair = generateNewKeyPair();
        RSAKey newKey = new RSAKey();
        newKey.setPrivateKey(Base64.getEncoder().encodeToString(newKeyPair.getPrivate().getEncoded()));
        newKey.setPublicKey(Base64.getEncoder().encodeToString(newKeyPair.getPublic().getEncoded()));
        newKey.setCreatedAt(LocalDateTime.now());
        newKey.setKeyId(UUID.randomUUID().toString());
        newKey.setActive(true);
        rsaKeyRepository.save(newKey);
        logger.info("Rotated RSA keys. New key ID: " + newKey.getKeyId());
    }

    @Transactional
    @Scheduled(cron = "#{@keyCleanupCron}")  // Key cleanup schedule
    public void cleanupInactiveKeys() {
        LocalDateTime cutoffTime = LocalDateTime.now().minusHours(1);  // Define the cutoff time (1 hour ago)
        int deletedKeys = rsaKeyRepository.deleteByActiveFalseAndCreatedAtBefore(cutoffTime);
        logger.info("Cleaned up " + deletedKeys + " inactive RSA keys older than 1 hour.");
    }


    private KeyPair generateNewKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating RSA key pair", e);
        }
    }

    // Method to find a public key for token verification (including inactive keys)
    public PublicKey getPublicKeyForVerification(String keyId) {
        RSAKey rsaKey = rsaKeyRepository.findByKeyId(keyId)
                .orElseThrow(() -> new RuntimeException("Key not found for ID: " + keyId));
        return getPublicKey(rsaKey.getPublicKey());
    }

    private PublicKey getPublicKey(String base64PublicKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate public key", e);
        }
    }
}
