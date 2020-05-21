package io.security.controller.user;


import io.security.domain.Account;
import io.security.domain.AccountDto;
import io.security.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {


    @Autowired
    UserService userService;

    @Autowired
    PasswordEncoder passwordEncoder;


    @GetMapping("/mypage")
    public String myPage() throws Exception{
        return "/user/mypage";

    }


    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";

    }

    @PostMapping("/users")
    public String creteUser(AccountDto accountDto) {
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        // modelMapper를 사용하면 AccountDto에 담긴 정보를
        // 도메인의 Account(== Account.class)로 맵핑 할수 있다
        account.setPassword(passwordEncoder.encode(account.getPassword()));
        userService.createUser(account);

        return "redirect:/";
    }


}
