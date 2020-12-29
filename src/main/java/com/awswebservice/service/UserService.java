package com.awswebservice.service;
//
//import com.awswebservice.domain.user.User;
//
//import java.util.Collection;
//
//public interface UserService {
//
//    User getUserById(long id);
//
//    User getUserByEmail(String email);
//
//    Collection<User> getAllUsers();
//
//    User create(UserBean userBean);
//}







import com.awswebservice.domain.user.Account;
import com.awswebservice.web.dto.AccountDto;

import java.util.List;

public interface UserService {

    void createUser(Account account);

    void modifyUser(AccountDto accountDto);

    List<Account> getUsers();

    AccountDto getUser(Long id);

    void deleteUser(Long idx);

    void order();
}