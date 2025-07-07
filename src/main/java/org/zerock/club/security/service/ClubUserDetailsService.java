package org.zerock.club.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.zerock.club.entity.ClubMember;
import org.zerock.club.repository.ClubMemberRepository;
import org.zerock.club.security.dto.ClubAuthMemberDTO;

import java.util.Optional;
import java.util.stream.Collectors;

@Log4j2
@Service
@RequiredArgsConstructor
public class ClubUserDetailsService implements UserDetailsService {

    private final ClubMemberRepository clubMemberRepository;
    private final PasswordEncoder passwordEncoder;  // BCryptPasswordEncoder 주입

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("ClubUserDetailsService loadUserByUsername " + username);

        Optional<ClubMember> result = clubMemberRepository.findByEmail(username, false);

        if(result.isEmpty()){
            throw new UsernameNotFoundException("Check Email or Social");
        }

        ClubMember clubMember = result.get();

        // 이메일 기반 사용자 정보와 비밀번호 확인
        if (clubMember.getPassword() == null || clubMember.getPassword().isEmpty()) {
            throw new BadCredentialsException("비밀번호 없음");
        }

        log.info("암호화된 비밀번호: " + clubMember.getPassword()); // 암호화된 비밀번호 로그 찍기

// 비밀번호 비교
        boolean isPasswordValid = passwordEncoder.matches("1111", clubMember.getPassword());
        log.info("비밀번호 비교 결과: " + isPasswordValid);  // 비밀번호 비교 결과 확인

        if (!isPasswordValid) {
            log.warn("비밀번호 비교 실패");
            throw new BadCredentialsException("비밀번호 다름");
        }

        // ClubAuthMemberDTO 생성
        ClubAuthMemberDTO clubAuthMember = new ClubAuthMemberDTO(
                clubMember.getEmail(),
                clubMember.getPassword(),
                clubMember.isFromSocial(),
                clubMember.getRoleSet().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                        .collect(Collectors.toSet())
        );
        if (clubMember.getPassword() != null) {
            clubAuthMember.setPassword(clubMember.getPassword());
        }


        log.info("회원 비밀번호: " + clubAuthMember.getPassword());

        clubAuthMember.setName(clubMember.getName());

        return clubAuthMember;
    }
}
