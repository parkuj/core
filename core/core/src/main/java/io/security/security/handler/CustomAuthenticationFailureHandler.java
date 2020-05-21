package io.security.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "아이디, 패스워드가 잘못됐습니다";

        if (exception instanceof BadCredentialsException){
            errorMessage = "아이디, 패스워드가 잘못됐습니다";
        }else if (exception instanceof InsufficientAuthenticationException){

            errorMessage ="잘못된 key";
        }
        setDefaultFailureUrl("/login?error=true&exception=" + exception.getMessage());


        super.onAuthenticationFailure(request, response, exception);
    }
}
