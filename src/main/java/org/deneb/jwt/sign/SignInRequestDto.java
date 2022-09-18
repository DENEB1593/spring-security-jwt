package org.deneb.jwt.sign;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class SignInRequestDto {

    private String id;

    private String password;

}