package com.nazim.authserver.payloads;

import lombok.Data;

@Data
public class TokenRefreshRequest {
    private String grantType;
}
