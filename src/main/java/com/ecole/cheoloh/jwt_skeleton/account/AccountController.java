package com.ecole.cheoloh.jwt_skeleton.account;


import com.ecole.cheoloh.jwt_skeleton.config.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.parameters.P;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RequiredArgsConstructor
@RestController
public class AccountController {

    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AccountRepository accountRepository;

    //회원가입
    @PostMapping("/join")
    public Long join(@RequestBody Map<String, String> account){
        return accountRepository.save(Account.builder()
                .email(account.get("email"))
                .password(passwordEncoder.encode(account.get("password")))
                .roles(Collections.singletonList("ROLE_USER"))
                .build()).getId();
    }

    //로그인
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> account){
        Account user = accountRepository.findByEmail(account.get("email"))
                .orElseThrow(()-> new IllegalArgumentException("가입되지 않은 E-MAIL입니다."));

        if (!passwordEncoder.matches(account.get("password"), user.getPassword())){
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }
        return jwtTokenProvider.createToken(user.getUsername(), user.getRoles());
    }

    @GetMapping("/accounts")
    public ResponseEntity<?> getMembers(){
        List<Account> members = accountRepository.findAll();
        return new ResponseEntity<>(members, HttpStatus.OK);
    }

    @GetMapping("/accounts/resource")
    public ResponseEntity<?> getResource(@RequestHeader Map<String, String> token){



    }
}
