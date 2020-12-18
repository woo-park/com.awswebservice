package com.awswebservice.web;

//import com.awswebservice.config.auth.LoginUser;
//import com.awswebservice.config.auth.dto.SessionUser;
import com.awswebservice.config.auth.LoginUser;
import com.awswebservice.config.auth.dto.SessionUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import javax.servlet.http.HttpSession;

@RequiredArgsConstructor
@Controller
public class IndexController {
//    private final PostsService postsService;
    private final HttpSession httpSession;        // no need due to @LoginUser Annotation

    @GetMapping("/")
    public String index(Model model, @LoginUser SessionUser user) {
//        model.addAttribute("posts", postsService.findAllDesc());

//        SessionUser user = (SessionUser) httpSession.getAttribute("user");    // no need due to @LoginUser Annotation

        if(user != null) {
            model.addAttribute("userName", user.getName());
        }

        return "index";
    }

    @GetMapping("/security_test")
    public String security_test(Model model, @LoginUser SessionUser user) {

        return "security_test";
    }


//
//    @GetMapping("/posts/save")
//    public String postsSave() {
//        return "posts-save";
//    }
//
//    @GetMapping("/posts/update/{id}")
//    public String postsUpdate(@PathVariable Long id, Model model) {
//        PostsResponseDto dto = postsService.findById(id);
//        model.addAttribute("post", dto);
//
//        return "posts-update";
//    }

}



/*
*
    HttpSession's setAttribute("Key", Value)
        "Key"를 사용하여 객체를 세션에 바인딩한다.
        Value는 값으로 들어올 자료형을 예측할 수 없기에 Object형으로 업캐스팅하여 모두 받아낸다.
    HttpSession's getAttribute("Key")
        "Key"로 바인딩된 객체를 돌려주고, "Key"로 바인딩된 객체가 없다면 null를 돌려준다.
        Value는 세션을 저장할 때 Object형으로 업캐스팅을 했으므로, 가져올 땐 원래대로 다운캐스팅 해야 한다.
    HttpServletRequest's getSession(true)
        이미 세션이 있다면 그 세션을 돌려주고, 세션이 없으면 새로운 세션을 생성한다.
        request.getSession()로 쓸 수 있다.
    HttpServletRequest's getSession(false)
        이미 세션이 있다면 그 세션을 돌려주고, 세션이 없으면 null을 돌려준다.

*
* */