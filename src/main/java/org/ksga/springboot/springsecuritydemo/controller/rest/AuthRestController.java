package org.ksga.springboot.springsecuritydemo.controller.rest;

import org.ksga.springboot.springsecuritydemo.model.auth.ERole;
import org.ksga.springboot.springsecuritydemo.model.auth.FacebookUser;
import org.ksga.springboot.springsecuritydemo.model.auth.Role;
import org.ksga.springboot.springsecuritydemo.model.auth.User;
import org.ksga.springboot.springsecuritydemo.payload.request.LoginRequest;
import org.ksga.springboot.springsecuritydemo.payload.request.RegisterRequest;
import org.ksga.springboot.springsecuritydemo.payload.response.JwtResponse;
import org.ksga.springboot.springsecuritydemo.payload.response.Response;
import org.ksga.springboot.springsecuritydemo.repository.RoleRepository;
import org.ksga.springboot.springsecuritydemo.repository.UserRepository;
import org.ksga.springboot.springsecuritydemo.security.jwt.JwtUtils;
import org.ksga.springboot.springsecuritydemo.security.service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/login")
    public Response<JwtResponse> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Set<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        return Response.<JwtResponse>ok().setPayload(
                new JwtResponse(jwt, userDetails.getId(), userDetails.getUsername())
        );
    }

    @PostMapping("/facebook")
    public String facebookLogin(@RequestBody FacebookUser facebookUser) {
        Optional<User> user = userRepository.findUserByFacebookId(facebookUser.getFacebookId());
        if (user.isEmpty()) {
            facebookUser.setPassword(encoder.encode(facebookUser.getFacebookId()));
            userRepository.insertFacebookUser(facebookUser);
        } else {
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(user.get().getUsername(), facebookUser.getFacebookId());
            authentication = authenticationManager.authenticate(authentication);
            return jwtUtils.generateJwtToken(authentication);
        }
        return null;
    }

    @PostMapping("/register")
    public Response<User> registerUser(@RequestBody RegisterRequest registerRequest) {
        try {
            if (userRepository.existsByUsername(registerRequest.getUsername())) {
                return Response
                        .<User>badRequest()
                        .setErrors("Error: Username is already taken!");
            }

            User user = new User(
                    registerRequest.getUsername(),
                    encoder.encode(registerRequest.getPassword())
            );

            Set<String> strRoles = registerRequest.getRoles();
            Set<Role> roles = new HashSet<>();

            if (strRoles == null) {
                Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                System.out.println(userRole);
                roles.add(userRole);
            } else {
                strRoles.forEach(role -> {
                    if ("admin".equals(role)) {
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role Admin is not found."));
                        roles.add(adminRole);
                    } else {
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role User is not found."));
                        roles.add(userRole);
                    }
                });
            }
            user.setRoles(roles);
            userRepository.save(user);

            return Response
                    .<User>ok()
                    .setPayload(user);
        } catch (RuntimeException ex) {
            return Response
                    .<User>exception()
                    .setSuccess(false)
                    .setErrors(ex.getMessage());
        }
    }
}
