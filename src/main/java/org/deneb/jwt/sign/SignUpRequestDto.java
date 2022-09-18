package org.deneb.jwt.sign;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class SignUpRequestDto {

    private String id;

    private String password;

    private String name;

}