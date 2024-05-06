package io.moshkabortman.springauthenticationserver.data;

import lombok.Data;

@Data
public class LoginRequest {

    private String username;
    private String password;

}
