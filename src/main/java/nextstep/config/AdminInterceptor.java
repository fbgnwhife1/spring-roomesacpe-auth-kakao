package nextstep.config;

import nextstep.auth.JwtTokenProvider;
import nextstep.config.auth.Auth;
import nextstep.support.UnAuthorizedException;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class AdminInterceptor extends HandlerInterceptorAdapter {
    private final JwtTokenProvider provider;

    public AdminInterceptor(JwtTokenProvider provider) {
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

        String userName = provider.getPrincipal(accessToken);

        String role = auth.toString();
        if ("ADMIN".equals(role)) {
            if (userName.equals("admin")) {
                return true;
            }

            throw new UnAuthorizedException();
        }

        if ("admin".equals(userName)) {
            return true;
        }

        if ("USER".equals(role)) {
            return true;
        }

        return super.preHandle(request, response, handler);
    }
}
