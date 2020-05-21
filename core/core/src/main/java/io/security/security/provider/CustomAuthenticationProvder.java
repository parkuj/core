package io.security.security.provider;


import io.security.domain.Account;
import io.security.security.common.FormWebAuthenticationDetails;
import io.security.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.naming.InsufficientResourcesException;

public class CustomAuthenticationProvder implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String)authentication.getCredentials();
        // 유저가 로그인시 입력한 username과 password가 담긴 인증객체가 autentication

        // UserDetails userDetails =  userDetailsService.loadUserByUsername(username);
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);
        if (! passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("잘못된 패스워드 입니다");
            
            // authentication 인증객체에서 username을 추출해서 DB에서 해당하는 유저가 존재하는지 
            // loadUserByUsername()메소드로 검증한다
            // 해당 유저가 존재하면 UserDetails타입의 객체가 반환된다
            // 우리는 UserDetails인터페이스를 구현하는 User클래스를 상속한 AccountContext를 따로 만들었다
            // 그래서 AccoutContext타입의 객체로 형변환을 하고 받아준다
            // 반환되는 객체가 있다는것은 해당하는 username에 해당하는 유저가 DB에 존재한다는 의미이다
            // 이번에는 passwordEncoder를 의존주입받아서 matches()메소드로 패스워드를 비교한다
            // autehtication 인증객체에서 꺼낸 password와 DB에서 반환받은 유저 객체의 패스워드를 비교한다
            // 만약 false이면 비밀번호가 불일치
        }
        FormWebAuthenticationDetails formWebAuthenticationDetails
                = (FormWebAuthenticationDetails)authentication.getDetails();

        String secretkey = formWebAuthenticationDetails.getSecretKey();

        if(secretkey == null || "secret".equals(secretkey)){
            throw new InsufficientAuthenticationException("secretkey가 일치하지 않습니다");


        }

        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(accountContext.getAccount(),
                null, accountContext.getAuthorities());

        return authenticationToken;
        
        // true이면 패스워드도 일치한다는 의미이기에 UsernamePasswordAuthenticationToken타입의 최종인증객체를 생성한다
        // 최종인증객체에는 보안을 위해 비밀번호는 null로 저장하고 accountContext에서 권한을 꺼내서 넣어준다
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    // authentcation 인증객체의 클래스 참고 ~ 해당형태로 쓴다고만 알고있자
    // 참조 instanceof
}
