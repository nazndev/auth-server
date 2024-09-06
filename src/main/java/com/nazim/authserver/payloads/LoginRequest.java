package com.nazim.authserver.payloads;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
    private String grantType;  // e.g. password, client_credentials, refresh_token
}
