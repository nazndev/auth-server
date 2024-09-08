package com.nazim.authserver.controllers;

import com.nazim.authserver.entities.RSAKey;
import com.nazim.authserver.repositories.RSAKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/.well-known/jwks.json")  // Standard endpoint
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class JWKSController {

    private final RSAKeyRepository rsaKeyRepository;

    @GetMapping
    public Map<String, Object> getJWKS() {
        RSAKey activeKey = rsaKeyRepository.findByActiveTrue()
                .orElseThrow(() -> new RuntimeException("No active RSA key found"));

        // Decode public key
        try {
            byte[] keyBytes = Base64.getDecoder().decode(activeKey.getPublicKey());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(spec);

            // Build JWKS response
            Map<String, Object> jwk = new HashMap<>();
            jwk.put("kty", "RSA");  // Key type
            jwk.put("use", "sig");  // Public key use, 'sig' for signature
            jwk.put("alg", "RS256");  // Algorithm
            jwk.put("kid", activeKey.getKeyId());  // Key ID
            jwk.put("n", Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPublicKey.getModulus().toByteArray()));  // Modulus
            jwk.put("e", Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPublicKey.getPublicExponent().toByteArray()));  // Exponent

            Map<String, Object> jwks = new HashMap<>();
            jwks.put("keys", new Map[] { jwk });

            return jwks;
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse public key", e);
        }
    }
}
