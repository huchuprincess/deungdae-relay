# 등대 공공데이터 중계

기상특보와 지진 공개 자료를 조회용 정적 JSON으로 만드는 독립 프로젝트입니다. 정부 공식 서비스가 아니며 경보 수신, 재발송, 푸시 알림을 제공하지 않습니다.

현재는 로컬 공개 후보입니다. 실제 서비스키, R2 계정, 도메인은 설정하지 않았습니다. 공개 저장소 생성과 배포도 하지 않았습니다. 후보 저장소 이름은 `huchuprincess/deungdae-relay`입니다.

## 키 없이 실행

Python 3.12 이상과 시간대 자료가 있는 환경에서 실행합니다. Python 외부 패키지를 설치하지 않습니다. Linux에서는 `Asia/Seoul` 시간대 자료가 필요합니다.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m relay.run --output /tmp/relay-unconfigured.json
PYTHONDONTWRITEBYTECODE=1 python3 -m relay.run --mode example --output /tmp/relay-example.json
PYTHONDONTWRITEBYTECODE=1 python3 -m relay.site --snapshot public/v1/latest.json --output /tmp/relay-site-preview
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_candidate.py
```

기본 실행과 `public/v1/latest.json`은 실제 조회 전 상태입니다. 성공 시각이 없으며 자료를 받은 것으로 표시하지 않습니다. 예제는 직접 만든 2000년 자료이고 `mode: example`과 예제 문구를 유지합니다. 원본 API 응답이나 실제 사건을 시험 자료로 복사하지 않았습니다.

## 중계와 배포

원본 발표 시각, 조회 성공 시각과 파일 생성 시각은 서로 다릅니다. 두 피드의 일부 또는 전체 조회가 실패해도 마지막 유효 자료와 성공 시각을 유지합니다. HTTP 200이어도 API 오류, 누락된 페이지, 오래된 응답, 자료의 후퇴는 실패로 처리합니다. 읽지 못하거나 손상된 이전 파일을 빈 성공 응답으로 대체하지 않습니다.

기본 배포 구성은 R2의 `v1/latest.json` 한 객체와 자체 HTTPS 도메인입니다. Pages 대체 경로도 같은 JSON 계약으로 준비했습니다. Pages 배포 의존성에서 취약점이 발견되어 해당 작업은 코드에서 잠갔습니다. 승인 변수만 바꿔 실행할 수 없습니다. 의존성 문제와 Pages 사용 적합성을 해결한 뒤 검토해야 합니다. 두 경로를 자동으로 전환하거나 동시에 배포하지 않습니다.

Actions는 10분 간격 구성입니다. 공개 승인 변수와 실서비스 확인 변수가 설정되기 전에는 수집과 배포 작업을 실행하지 않습니다. 키를 코드, 앱, JSON이나 명령줄 인자로 전달하지 않고 승인 후 작업 비밀값으로만 받습니다. 원격 작업은 현재 실행하지 않았습니다.

## 현재 확인 범위

확인한 특보 목록 API에는 제목과 발표 시각이 있습니다. 이를 지역별 현재 활성 특보 목록으로 해석하지 않습니다. 적용, 해제, 만료 시각과 활성 상태를 제목에서 추측하지 않으며 값은 미확인으로 둡니다. 따라서 현재 후보는 `특보 없음`을 확정하지 않습니다. 해제 기록도 활성 특보로 표시하지 않습니다. 지역별 활성 여부 확인은 현황 API의 공식 구조를 확인하고 시험한 뒤 별도로 검토해야 합니다.

지진은 발생 시각을 가진 발표 기록입니다. 예전 지진을 현재 사건으로 표현하지 않습니다. 자료가 오래되거나 조회가 실패해도 안전을 뜻하는 문구를 만들지 않습니다.

출처와 이용 조건은 [출처 확인](docs/sources.md), JSON과 표시 규칙은 [자료 계약](docs/contract.md), 계정 준비와 비활성 배포 구성은 [운영 준비](docs/operations.md)에 정리했습니다. 공개할 전체 파일은 [PUBLIC_FILES.txt](PUBLIC_FILES.txt)입니다. 코드 이용 허락은 [권리 범위](RIGHTS.md)를 따릅니다.

공개 전 검사는 [보안과 공개 절차](docs/security.md)를 따릅니다. [의존성 검사](docs/dependencies.md)에는 해소한 경로와 Pages 차단 사유가 있습니다. 원격 저장소를 만들기 전이라 [이슈 본문](docs/issue-draft.md)과 [draft PR 본문](docs/pr-draft.md)을 파일로 준비했습니다.
