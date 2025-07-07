package org.zerock.club.controller;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.zerock.club.security.dto.ClubAuthMemberDTO;

@Controller
@Log4j2
@RequestMapping("/sample/")
public class SampleController {

    @PreAuthorize("permitAll()")
    @GetMapping("/all")
    public void exAll() {
        log.info("exAll............");
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/member") // 컨트롤러에서 @AuthenticationPrincipal을 통해 로그인한 사용자 확인 가능
    public void exMember(@AuthenticationPrincipal ClubAuthMemberDTO clubAuthMember) {
        log.info("exMember.............");

        log.info("-----------------------");
        log.info(clubAuthMember);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public void exAdmin() {
        log.info("exAdmin............");
    }

    // (DTO 값) clubAuthMember == 파라미터(서비스에서 DTO로 반환)
    @PreAuthorize("#clubAuthMember != null && #clubAuthMember.username eq \"user95@zerock.org\"")
    @GetMapping("/exOnly")
    public String exMemberOnly(@AuthenticationPrincipal ClubAuthMemberDTO clubAuthMember){

        log.info("exMemberOnly.............");
        log.info(clubAuthMember);

        return "/sample/admin";
    }
}
