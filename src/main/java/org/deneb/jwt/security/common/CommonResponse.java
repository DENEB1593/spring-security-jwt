package org.deneb.jwt.security.common;


import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum CommonResponse {

    SUCCESS(0, "Success"),
    FAIL(-1, "Fail");

    private final int code;
    private final String message;
}
