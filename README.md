# RefreshToken
1. 클라이언트 측 로그인 요청(인증)<br>
* 요청 정보 토대로 authenticationToken 생성 -> Authentication 객체 생성 -> authenticationManager를 통해 회원정보 검증 <br>
* 인증이 완료되면 Token(Access, Refresh) 생성 -> 응답 헤더를 통해 토큰(Access, Refresh) 전달
* RefreshToken 저장 (Redis) <br><br>
2. 클라이언트 측 로그아웃 요청<br>
* 요청 헤더의 Token(Access, Refresh) 정보를 토대로 검증
* 검증이 완료 Redis 정보 수정
  * 로그아웃한 사용자의 AccessToken은 더이상 사용할 수 없어야 하는데 이미 클라이언트로 발급된 토큰을 서버에서 삭제할 수 없으니 <br>해당 토큰을 redis에 블랙리스트 처리  
  *  삭제 - key(username) , value(RefreshToken)  
  *  추가 - key(AccessToken), value("logout")<br><br>

3. 검증 
   * 요청 헤더의 AccessToken 유효성 체크
   * 유효하다면 유저 정보를 담은 Authentication 객체를 생성하여 SecurityContextHolder에 저장
   * 클라이언트의 요청 수락 <br><br>

⭐️<br>
   로그인 요청 간 생성한 <b>Authentication</b> 객체는 사용자의 인증 상태를 나타내고 이 후 메모리 해제<br>
   검증 간 생성한 <b>Authentication</b> 객체는 인증된 사용자의 정보 + 권한을 나타내고  SecurityContextHolder에 저장하여 세션이 유지되는 동안 검증에 사용
  
  
