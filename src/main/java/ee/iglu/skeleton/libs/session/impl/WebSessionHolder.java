package ee.iglu.skeleton.libs.session.impl;

import ee.iglu.skeleton.libs.session.ApiSessionHolder;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;

@Component
@RequiredArgsConstructor
class WebSessionHolder implements ApiSessionHolder {

    private static final String COOKIE_NAME = "session";
    private final HttpServletRequest request;
    private final HttpServletResponse response;

    public String getToken() {
        return getCookie(COOKIE_NAME);
    }

    public void setToken(String token) {
        setCookie(COOKIE_NAME, token);
    }

    private String getCookie(String cookieName) {
        if (request.getCookies() == null) {
            return null;
        }

        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(cookieName))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private void setCookie(String cookieName, String token) {
        Cookie cookie = new Cookie(cookieName, token);
        // TODO: use secure cookies
        //		cookie.setSecure(true);
        cookie.setMaxAge(Integer.MAX_VALUE);
        cookie.setHttpOnly(true);
        cookie.setPath("/api/");

        response.addCookie(cookie);
    }

}
