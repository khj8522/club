package org.zerock.club.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import net.minidev.json.JSONObject;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.club.security.util.JWTUtil;

import java.io.IOException;
import java.io.PrintWriter;

@Log4j2
public class ApiCheckFilter extends OncePerRequestFilter {

    private AntPathMatcher antPathMatcher;

    private String pattern;

    private JWTUtil jwtUtil;

    public ApiCheckFilter(String pattern, JWTUtil jwtUtil) {
        this.antPathMatcher = new AntPathMatcher();
        this.pattern = pattern;
        this.jwtUtil = jwtUtil; // 받아온 비밀 키 주입
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {

        log.info("REQUESTURI: " + request.getRequestURI());

        log.info(antPathMatcher.match(pattern,request.getRequestURI())); // 패턴 확인 (맞으면 true)

        if(antPathMatcher.match(pattern,request.getRequestURI())) {

            log.info("ApiCheckFilter..................................................");
            log.info("ApiCheckFilter..................................................");
            log.info("ApiCheckFilter..................................................");

            boolean checkHeader = checkAuthHeader(request);

            if(checkHeader) { // 인증이 되었다면
                filterChain.doFilter(request, response);
                return;
            } else {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                // json 리턴 및 한글깨짐 수정
                response.setContentType("application/json;charset=UTF-8"); // 응답 형식 타입 지정
                JSONObject json = new JSONObject();
                String message = "FAIL CHECK API TOKEN";
                json.put("code","403");
                json.put("message",message);

                PrintWriter out = response.getWriter();
                out.print(json);
                return;

            }

        }

        filterChain.doFilter(request,response); // 다음 필터 실행
    }

    private boolean checkAuthHeader(HttpServletRequest request) {

        boolean checkResult = false;

        String authHeader = request.getHeader("Authorization");

        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            log.info("Authorization exist: " + authHeader);

            try {
                String email = jwtUtil.validateAndExtract(authHeader.substring(7)); // 토큰 비교
                log.info("validate result : " + email);
                checkResult = email.length() > 0;

            } catch (Exception e) {
                e.printStackTrace();
            }

        }
    return checkResult;
    }
}
