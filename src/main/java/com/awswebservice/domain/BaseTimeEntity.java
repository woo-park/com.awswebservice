//package com.awswebservice.domain;
//
//import lombok.Getter;
//import org.springframework.data.annotation.CreatedDate;
//import org.springframework.data.annotation.LastModifiedDate;
//import org.springframework.data.jpa.domain.support.AuditingEntityListener;
//
//import javax.persistence.EntityListeners;
//import javax.persistence.MappedSuperclass;
//import java.time.LocalDateTime;
//
//@Getter
//@MappedSuperclass                               // JPA Entity class가 상속할 경우 private fields를 인식 가능하게
//@EntityListeners(AuditingEntityListener.class)  // BaseTimeEntity class에 Auditing 기능을 포함 시킴
//public abstract class BaseTimeEntity {
//    @CreatedDate
//    private LocalDateTime createdDate;  // entity 가 저장될때 자동으로
//
//    @LastModifiedDate
//    private LocalDateTime modifiedDate; // entity 가 수정될때 자동으로
//}
