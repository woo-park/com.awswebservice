package com.awswebservice.web.user;

import com.awswebservice.domain.user.Account;
import com.awswebservice.service.UserService;
import com.awswebservice.web.dto.AccountDto;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/mypage")
    public String myPage() throws Exception {

        return "user/mypage";
    }

    @GetMapping(value = "/users")                                   // hmmm interesting approach: using term 'users' as registering page, and also as a receiving portal for post method
    public String createUser(){
        return "user/login/register";
    }

    @PostMapping(value ="/users")
    public String createUser(AccountDto accountDto) {
        //ModelMapper api 를 사용한다, 그러면 dto를 바로 model로 map할수있다
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        System.out.println(account);
        System.out.println(accountDto);
        System.out.println(account.getName());
        System.out.println(account.getPassword());
        account.setPassword(passwordEncoder.encode(account.getPassword()));

        userService.createUser(account);


        return "redirect:/";
    }



//    @Autowired
//    private UserService userService;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Autowired
//    private RoleRepository roleRepository;
//
//    @GetMapping(value="/users")
//    public String createUser() throws Exception {
//
//        return "user/login/register";
//    }
//
//    @PostMapping(value="/users")
//    public String createUser(AccountDto accountDto) throws Exception {
//
//        ModelMapper modelMapper = new ModelMapper();
//        Account account = modelMapper.map(accountDto, Account.class);
//        account.setPassword(passwordEncoder.encode(accountDto.getPassword()));
//
//        userService.createUser(account);
//
//        return "redirect:/";
//    }
//
//    @GetMapping(value="/mypage")
//    public String myPage(@AuthenticationPrincipal Account account, Authentication authentication, Principal principal) throws Exception {
//        return "user/mypage";
//    }
//
//    @GetMapping("/order")
//    public String order(){
//        userService.order();
//        return "user/mypage";
//    }
}
