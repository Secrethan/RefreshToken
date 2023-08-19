# RefreshToken
1. 클라이언트의 인증 요청 시 전달 받은 정보를 토대로 DB 데이터와 비교 후 refresh, access token 생성
2. 클라이언트 측에 refresh, access token 전달, 클라이언트 측 저장소는 미정(로컬 스토리지, 세션 스토리지, 쿠키 중 선택할 예정임)
3. 클라이언트는 모든 요청에 토큰 전달
4. access token 만료 시 재발급 (미구현)
