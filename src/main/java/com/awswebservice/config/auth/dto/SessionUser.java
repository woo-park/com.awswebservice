package com.awswebservice.config.auth.dto;

import com.awswebservice.domain.user.Account;
import lombok.Getter;

import java.io.Serializable;


@Getter
public class SessionUser implements Serializable {  //직렬화 기능을 가진 session Dto를 하나 추가로 만드는것이 유지보수에 도움이됩니다
    private String name;
    private String email;
    private String picture;

    public SessionUser(Account user) {
        this.name = user.getName();
        this.email = user.getEmail();
        this.picture = user.getPicture();
    }
}


/*
* SessionUser에는 인증된 사용자 정보만 필요 -> only name, email, picture
*
* 왜 User class를 사용하면 안되나요?
*
* User class를 그대로 사용했다면... Failed to convert from type... error
*
* 이는 User class를 session에 저장하려하니, User class에 직렬화를 구현하지 않았다는 의미의 error
*
* User class가 Entity이기 때문입니다
*
* Entity class는 언제 다른 Entity와 관계가 형성될지 모릅니다
*
* @OneToMany
* @ManyToMany
* 등 자식 엔티티를 갖고있다면 -> 직렬화 대상에 자식들까지 포함되니
* 성는 이슈, 부수 효과 가 발생할 가능성이 높습니다.
*
* 그래서 직렬화 기능을 가진 session Dto를 추가합니다. data to object
*
*
*
*
*
*
* */