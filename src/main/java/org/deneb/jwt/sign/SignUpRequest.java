package org.deneb.jwt.sign;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString
public class SignUpRequest {
    private final String id;
    private final String password;
    private final String name;
    private final String role;
}
