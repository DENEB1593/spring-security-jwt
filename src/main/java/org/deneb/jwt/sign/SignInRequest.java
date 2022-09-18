package org.deneb.jwt.sign;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class SignInRequest {
    private final String id;
    private final String password;
}
