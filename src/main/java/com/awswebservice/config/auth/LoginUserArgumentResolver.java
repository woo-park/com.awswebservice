package com.awswebservice.config.auth;


import com.awswebservice.config.auth.dto.SessionUser;
import lombok.RequiredArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpSession;

// overrides two methods -> supportsParameter && resolveArgument


@RequiredArgsConstructor    //requires argument -> must be passed in -> during the initiating
@Component
public class LoginUserArgumentResolver implements HandlerMethodArgumentResolver {
    private final HttpSession httpSession;

    @Override //Override HandlerMethodArgumentResolver's Bool-Sup-Param method
    public boolean supportsParameter(MethodParameter parameter) {

        boolean isLoginUserAnnotation = parameter.getParameterAnnotation(LoginUser.class) != null;  // as a middleware, we can intercept parameter and check if @LoginUser annotaion exists // remarkable
        //LoginUser.class is the custom created @Annotation

        boolean isUserClass = SessionUser.class.equals(parameter.getParameterType());  // ? getParamType?  // passed in arg should have type of SessionUser

        /*
            oooo
            public String index(Model model, @LoginUser SessionUser user) {
                model.addAttribute("posts", postsService.....)
            }

         */

        return isLoginUserAnnotation && isUserClass;    // returns true -> if both are true
    }

    @Override       // parameter 에 전달한 object를 생성 합니다
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        return httpSession.getAttribute("user");    // like how it was done manually / everytime you need session object
    }

}
