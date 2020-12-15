package com.awswebservice.security;


import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;


import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@RunWith(SpringRunner.class)    // JUnit 과 springboot test 연결자 역활
//@WebMvcTest // @Controller ok , @Service, @Component, @Repository 사용 불가능
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class ApplicationTest {
//    @Autowired // 스프링이 관리하는 bean을 받습니다
//    private MockMvc mvc;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void security_test가_리턴된다() throws Exception {
        String hello = "Spring Security 권한 관리";

        //when
        String body = this.restTemplate.getForObject("/security_test", String.class);

        //then
        assertThat(body).contains(hello);
    }



}