package org.ksga.springboot.springsecuritydemo.model.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class FacebookUser {
    private String username;
    @JsonIgnore
    private String password;
    @JsonIgnore
    private final String provider = "facebook";
    private String facebookId;
}
