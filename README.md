## 기능 요구사항
- 토큰 발급하는 API 생성
- 내 정보 조회하기
  - 토큰을 이용하여 본인 정보 응답하기
- 예약하기, 예약취소 개선
  - 아래의 API 설계에 맞춰 API 스펙을 변경한다.
  - 비로그인 사용자는 예약이 불가능하다.
  - 자신의 예약이 아닌 경우 예약 취소가 불가능하다.
  
## 프로그래밍 요구사항
- 인증 로직은 Controller에서 구현하기 보다는 재사용이 용이하도록 분리하여 구현하다.
  - 가능하면 Controller와 인증 로직을 분리한다.
- 토큰을 이용한 인증 프로세스에 대해 이해가 어려운 경우 페어와 함께 추가학습을 진행한다.
- HandlerMethodArgumentResolver를 활용한다.