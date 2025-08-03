# Spring Security + JWT 인증 기반 보안 처리 웹 애플리케이션

## 프로젝트 소개  
Spring Security와 JWT(Json Web Token)를 활용해 인증 및 권한 처리를 구현한 웹 애플리케이션입니다.  
로그인 시 JWT 토큰을 발급하고, 이후 사용자의 요청은 해당 토큰을 기반으로 인증됩니다.  
또한, OAuth2 기반 로그인도 구현하여 소셜 로그인을 연습했고, CORS 정책 처리 및 Security 필터 체인을 커스터마이징하여 보안 흐름을 직접 구성했습니다.

## 사용 기술
- Spring Boot  
- Spring Security  
- JWT  
- OAuth2 로그인 (Google 등)  
- CORS 정책 처리  
- BCryptPasswordEncoder (비밀번호 암호화)

## 주요 기능

### 로그인 및 인증
- Form 기반 로그인 구현  
- JWT 토큰 발급: 서버 비밀키를 사용해 토큰 서명  
- JWT 토큰 검증: 클라이언트가 요청 시 헤더에 토큰 포함 → 서버 비밀키로 해시 검증  

### 인증 필터 흐름
- `LoginFilter`: 로그인 시 서버 비밀키로 JWT 생성 후 클라이언트에 전달  
- `CheckFilter`: 사용자의 모든 요청에서 JWT를 헤더로 받아, 서버에서 검증 후 인증 처리  
- JWT 없이 접근 시 인증 실패 처리

### OAuth 로그인
- Spring Security OAuth2를 이용해 구글 등 외부 로그인 기능 구현  

### 권한 처리
- `/sample/all`: 전체 공개  
- `/sample/member`: 인증된 사용자만 접근 가능  
- 향후 ROLE 분리에 따라 접근 권한 확장 가능

### 회원 데이터 처리
- 이메일, 암호화된 비밀번호(DB 저장 시 BCryptPasswordEncoder 사용)  
- JWT에는 사용자 ID/Email 등 필요한 정보를 담아 인증 시 파싱

### CORS 정책 처리
- JWT 기반 API 통신을 위해 CORS 정책을 설정하여 프론트와 백엔드 간 통신 가능하도록 설정  
- 특정 Origin, Method, Header 제한

## 실행 방법
1. 프로젝트 실행  
2. 로그인 요청 → JWT 발급 → JWT 포함된 요청으로 인증 필요한 페이지 접근  
3. 예시:
   - 전체 접근 가능: [http://localhost:8080/sample/all](http://localhost:8080/sample/all)  
   - 로그인 필요: [http://localhost:8080/sample/member](http://localhost:8080/sample/member)

## 배운 점
- Spring Security의 필터 체인 구조와 인증 처리 과정을 이해하게 되었습니다.  
- JWT 생성 및 서명 처리, 헤더 인증 구조를 직접 구현하며 실전 감각을 익혔습니다.  
- OAuth 로그인 및 CORS 정책 설정 등 보안 관련 실무 요소를 경험했습니다.
