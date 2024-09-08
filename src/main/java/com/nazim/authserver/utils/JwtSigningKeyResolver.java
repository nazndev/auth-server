package com.nazim.authserver.utils;

import com.nazim.authserver.entities.RSAKey;
import com.nazim.authserver.repositories.RSAKeyRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.PublicKey;

@Component
public class JwtSigningKeyResolver implements SigningKeyResolver {

    private final RSAKeyRepository rsaKeyRepository;
    private final JwtTokenUtil jwtTokenUtil;

    @Autowired
    public JwtSigningKeyResolver(RSAKeyRepository rsaKeyRepository, JwtTokenUtil jwtTokenUtil) {
        this.rsaKeyRepository = rsaKeyRepository;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Override
    public PublicKey resolveSigningKey(JwsHeader header, Claims claims) {
        String kid = header.getKeyId();  // Extract key ID (kid) from JWT header
        RSAKey rsaKey = rsaKeyRepository.findByKeyId(kid)  // Use findByKeyId instead of findById
                .orElseThrow(() -> new RuntimeException("RSA Key not found for keyId: " + kid));

        return jwtTokenUtil.getPublicKey(rsaKey.getPublicKey());
    }

    @Override
    public PublicKey resolveSigningKey(JwsHeader header, String plaintext) {
        // Implement if needed for plaintext
        return null;
    }
}
