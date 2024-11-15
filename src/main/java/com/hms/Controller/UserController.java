package com.hms.Controller;


import com.hms.Entity.AppUser;
import com.hms.Repository.AppUserRepository;
import com.hms.Service.UserService;
import com.hms.Payload.LoginDto;
import com.hms.Payload.TokenDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private UserService userService;
    private AppUserRepository appUserRepository;

    public UserController(UserService userService, AppUserRepository appUserRepository) {
        this.userService = userService;
        this.appUserRepository = appUserRepository;
    }

    @PostMapping("/signUp")
    public ResponseEntity<?> createAppUser(@RequestBody AppUser user) {
        Optional<AppUser> opUser = appUserRepository.findByUsername(user.getUsername());
        if (opUser.isPresent()) {
            return new ResponseEntity<>("user already exist", HttpStatus.INTERNAL_SERVER_ERROR);
        }
        Optional<AppUser> opEmail = appUserRepository.findByEmail(user.getEmail());
        if (opEmail.isPresent()) {
            return new ResponseEntity<>("Email already exist", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        String encrypt = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt(5));
        user.setPassword(encrypt);
        user.setRole("USER_ROLE");
        AppUser savedUser = appUserRepository.save(user);
        return new ResponseEntity<>(savedUser, HttpStatus.CREATED);

    }
    @PostMapping("/login")
public ResponseEntity<?> createLogin(@RequestBody LoginDto dto){
        String token = userService.login(dto);

if(token!=null){
    TokenDto tokenDto=new TokenDto();
    tokenDto.setToken(token);
    tokenDto.setType("JWT");
    return new ResponseEntity<>(tokenDto,HttpStatus.OK);
}else{
    return new ResponseEntity<>("invalid username/password",HttpStatus.FORBIDDEN);
}
    }

    @PostMapping("/signUpOwner")
    public ResponseEntity<?> createAppUserOwner(@RequestBody AppUser user) {
        Optional<AppUser> opUser = appUserRepository.findByUsername(user.getUsername());
        if (opUser.isPresent()) {
            return new ResponseEntity<>("user already exist", HttpStatus.INTERNAL_SERVER_ERROR);
        }
        Optional<AppUser> opEmail = appUserRepository.findByEmail(user.getEmail());
        if (opEmail.isPresent()) {
            return new ResponseEntity<>("Email already exist", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        String encrypt = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt(5));
        user.setPassword(encrypt);
        user.setRole("OWNER_ROLE");
        AppUser savedUser = appUserRepository.save(user);
        return new ResponseEntity<>(savedUser, HttpStatus.CREATED);

    }

}