package com.hms.Service;


import com.hms.Entity.AppUser;
import com.hms.Repository.AppUserRepository;
import com.hms.Payload.LoginDto;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
public class UserService {
    private AppUserRepository appUserRepository;

    private JwtService jwtService;;

    public UserService(AppUserRepository appUserRepository, JwtService jwtService) {
        this.appUserRepository = appUserRepository;
        this.jwtService = jwtService;
    }

    public String login(LoginDto dto){
        Optional<AppUser> opUserName = appUserRepository.findByUsername(dto.getUsername());

if(opUserName.isPresent()){
    AppUser appUser = opUserName.get();

    if( BCrypt.checkpw(dto.getPassword(),appUser.getPassword())){
        String token = jwtService.generateToken(appUser.getUsername());
        return token;
    }
}else{
    return null;
}
 return  null;
    }
}
