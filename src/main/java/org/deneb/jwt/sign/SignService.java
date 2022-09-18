package org.deneb.jwt.sign;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.deneb.jwt.security.JwtTokenProvider;
import org.deneb.jwt.security.common.CommonResponse;
import org.deneb.jwt.user.User;
import org.deneb.jwt.user.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;


@Slf4j
@Service
@AllArgsConstructor
public class SignService {

    private UserRepository userRepository;
    private JwtTokenProvider jwtTokenProvider;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public SignUpResultDto signUp(String id, String password, String name, String role) {
        log.info("[getSignUpResult] 회원 가입 정보 전달");
        User user;
        if (role.equalsIgnoreCase("admin")) {
            user = User.builder()
                .uid(id)
                .name(name)
                .password(bCryptPasswordEncoder.encode(password))
                .roles(Collections.singletonList("ROLE_ADMIN"))
                .build();
        } else {
            user = User.builder()
                .uid(id)
                .name(name)
                .password(bCryptPasswordEncoder.encode(password))
                .roles(Collections.singletonList("ROLE_USER"))
                .build();
        }

        User savedUser = userRepository.save(user);
        SignUpResultDto signUpResultDto = new SignInResultDto();

        log.info("[getSignUpResult] userEntity 값이 들어왔는지 확인 후 결과값 주입");
        if (!savedUser.getName().isEmpty()) {
            log.info("[getSignUpResult] 정상 처리 완료");
            setSuccessResult(signUpResultDto);
        } else {
            log.info("[getSignUpResult] 실패 처리 완료");
            setFailResult(signUpResultDto);
        }
        return signUpResultDto;
    }

    public SignInResultDto signIn(String id, String password) throws RuntimeException {
        log.info("[getSignInResult] signDataHandler 로 회원 정보 요청");
        User user = userRepository.getByUid(id);
        log.info("[getSignInResult] Id : {}", id);

        log.info("[getSignInResult] 패스워드 비교 수행");
        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException();
        }
        log.info("[getSignInResult] 패스워드 일치");

        log.info("[getSignInResult] SignInResultDto 객체 생성");
        SignInResultDto signInResultDto = SignInResultDto.builder()
            .token(jwtTokenProvider.createToken(String.valueOf(user.getUid()),
                user.getRoles()))
            .build();

        log.info("[getSignInResult] SignInResultDto 객체에 값 주입");
        setSuccessResult(signInResultDto);

        return signInResultDto;
    }

    // 결과 모델에 api 요청 성공 데이터를 세팅해주는 메소드
    private void setSuccessResult(SignUpResultDto result) {
        result.setSuccess(true);
        result.setCode(CommonResponse.SUCCESS.getCode());
        result.setMsg(CommonResponse.SUCCESS.getMessage());
    }

    // 결과 모델에 api 요청 실패 데이터를 세팅해주는 메소드
    private void setFailResult(SignUpResultDto result) {
        result.setSuccess(false);
        result.setCode(CommonResponse.FAIL.getCode());
        result.setMsg(CommonResponse.FAIL.getMessage());
    }
}