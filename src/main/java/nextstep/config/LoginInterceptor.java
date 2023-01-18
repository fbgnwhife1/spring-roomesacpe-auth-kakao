package nextstep.config;

import nextstep.auth.JwtTokenProvider;
import nextstep.config.auth.Auth;
import nextstep.support.UnAuthorizedException;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class LoginInterceptor extends HandlerInterceptorAdapter {
    private final JwtTokenProvider provider;

    public LoginInterceptor(JwtTokenProvider provider) {
        this.provider = provider;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        HandlerMethod handlerMethod = (HandlerMethod) handler;
        Auth auth = handlerMethod.getMethodAnnotation(Auth.class);

        if (auth == null) {
            return true;
        }

        HttpSession session = request.getSession();
        if (session == null) {
            throw new UnAuthorizedException();
        }

        String accessToken = request.getHeader("Authorization");
        if (accessToken == null) {
            throw new UnAuthorizedException();
        }

        String role = auth.toString();
        if ("USER".equals(role)) {
            return true;
        }

        if ("ADMIN".equals(role)) {
            if (provider.getPrincipal(accessToken).equals("admin")) {
                return true;
            }

            throw new UnAuthorizedException();
        }

        return super.preHandle(request, response, handler);
    }
}
