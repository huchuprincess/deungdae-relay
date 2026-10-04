# 의존성 검사

중계, 검증과 R2 저장 코드는 Python 3.12 표준 라이브러리만 사용합니다. 외부 Python/Node 패키지는 설치하지 않습니다. Python, Git과 시간대 자료는 실행 환경에서 제공합니다.

2026-10-04에 공식 저장소의 고정 커밋 `package-lock.json`을 `npm audit --ignore-scripts --omit=dev --json`으로 검사했습니다. 패키지 설치와 lifecycle 스크립트는 실행하지 않았습니다. npm 버전은 11.9.0입니다. 수치는 경고를 받은 패키지 이름 수이며, 서로 독립적인 취약점 수나 공격 재현 건수가 아닙니다. lock 검사만으로 배포 번들과 모든 취약 기능의 사용 여부를 입증할 수는 없습니다.

| 공식 Action | 검사한 버전 | 경고와 조치 |
|---|---|---|
| actions/checkout | v7.0.1 | high 1개. CI와 R2에서 제거하고 인증 helper 없는 네이티브 Git으로 대체 |
| actions/deploy-pages | v5.0.1 | critical 1, high 9, moderate 12개. Pages build/deploy 실행 잠금 |
| actions/upload-pages-artifact | v5.0.0 | 자체 Node 의존성은 없는 composite이며 내부 upload-artifact v7.0.0을 호출. 잠긴 구성에만 존재 |
| actions/upload-artifact | v7.0.0 및 v7.0.1 | 두 버전 모두 high 5개. 최신 버전 교체만으로 해소되지 않음 |

## Pages를 잠근 정확한 패키지

| deploy-pages v5.0.1 패키지 | 설치 버전 | 최고 경고 | 직접 권고 또는 영향 경로 |
|---|---|---|---|
| `@actions/artifact` | 2.1.8 | moderate | @actions/github → @octokit/core를 통한 영향 |
| `@actions/core` | 1.10.1 | moderate | uuid를 통한 영향 |
| `@actions/github` | 5.1.1 | moderate | @octokit/core → @octokit/plugin-paginate-rest를 통한 영향 |
| `@azure/core-http` | 3.0.4 | moderate | uuid를 통한 영향 |
| `@azure/storage-blob` | 12.17.0 | moderate | @azure/core-http를 통한 영향 |
| `@fastify/busboy` | 2.1.0 | high | [GHSA-x8mw-p69m-v3mx](https://github.com/advisories/GHSA-x8mw-p69m-v3mx) |
| `@octokit/core` | 3.6.0 | moderate | @octokit/graphql → @octokit/request → @octokit/request-error를 통한 영향 |
| `@octokit/graphql` | 4.8.0 | moderate | @octokit/request를 통한 영향 |
| `@octokit/plugin-paginate-rest` | 2.21.3, 9.1.5 | moderate | [GHSA-h5c3-5r3r-rr8q](https://github.com/advisories/GHSA-h5c3-5r3r-rr8q) |
| `@octokit/request` | 5.6.3, 8.1.6 | moderate | [GHSA-rmvr-2pp2-xj38](https://github.com/advisories/GHSA-rmvr-2pp2-xj38) |
| `@octokit/request-error` | 2.1.0, 5.0.1 | moderate | [GHSA-xx4v-prfh-6cgc](https://github.com/advisories/GHSA-xx4v-prfh-6cgc) |
| `brace-expansion` | 1.1.11, 2.0.1 | high | [GHSA-3jxr-9vmj-r5cp](https://github.com/advisories/GHSA-3jxr-9vmj-r5cp), [GHSA-6j4f-fj2g-mc7p](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p), [GHSA-f886-m6hf-6m8v](https://github.com/advisories/GHSA-f886-m6hf-6m8v), [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg), [GHSA-q2hr-2g5m-vwhr](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr), [GHSA-qhr7-859c-m2p7](https://github.com/advisories/GHSA-qhr7-859c-m2p7), [GHSA-rgw5-rvv9-x895](https://github.com/advisories/GHSA-rgw5-rvv9-x895), [GHSA-v6h2-p8h4-qcjw](https://github.com/advisories/GHSA-v6h2-p8h4-qcjw) |
| `cross-spawn` | 7.0.3 | high | [GHSA-3xgq-45jj-v275](https://github.com/advisories/GHSA-3xgq-45jj-v275) |
| `form-data` | 4.0.0 | critical | [GHSA-fjxv-7rqg-78g4](https://github.com/advisories/GHSA-fjxv-7rqg-78g4), [GHSA-hmw2-7cc7-3qxx](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx) |
| `glob` | 10.3.12 | high | [GHSA-5j98-mcp5-4vw2](https://github.com/advisories/GHSA-5j98-mcp5-4vw2) |
| `lodash` | 4.17.21 | high | [GHSA-f23m-r3pf-42rh](https://github.com/advisories/GHSA-f23m-r3pf-42rh), [GHSA-r5fr-rjxr-66jc](https://github.com/advisories/GHSA-r5fr-rjxr-66jc), [GHSA-xxjr-mmjv-4gpg](https://github.com/advisories/GHSA-xxjr-mmjv-4gpg) |
| `minimatch` | 3.1.2, 5.1.6, 9.0.4 | high | [GHSA-23c5-xmqv-rm74](https://github.com/advisories/GHSA-23c5-xmqv-rm74), [GHSA-3ppc-4f35-3m26](https://github.com/advisories/GHSA-3ppc-4f35-3m26), [GHSA-7r86-cg39-jmmj](https://github.com/advisories/GHSA-7r86-cg39-jmmj) |
| `path-to-regexp` | 6.2.1 | high | [GHSA-9wv6-86v2-598j](https://github.com/advisories/GHSA-9wv6-86v2-598j) |
| `undici` | 5.28.2 | high | [GHSA-2mjp-6q6p-2qxm](https://github.com/advisories/GHSA-2mjp-6q6p-2qxm), [GHSA-35p6-xmwp-9g52](https://github.com/advisories/GHSA-35p6-xmwp-9g52), [GHSA-3787-6prv-h9w3](https://github.com/advisories/GHSA-3787-6prv-h9w3), [GHSA-4992-7rv2-5pvq](https://github.com/advisories/GHSA-4992-7rv2-5pvq), [GHSA-8xcm-r25x-g524](https://github.com/advisories/GHSA-8xcm-r25x-g524), [GHSA-9qxr-qj54-h672](https://github.com/advisories/GHSA-9qxr-qj54-h672), [GHSA-c76h-2ccp-4975](https://github.com/advisories/GHSA-c76h-2ccp-4975), [GHSA-cxrh-j4jr-qwg3](https://github.com/advisories/GHSA-cxrh-j4jr-qwg3), [GHSA-g8m3-5g58-fq7m](https://github.com/advisories/GHSA-g8m3-5g58-fq7m), [GHSA-g9mf-h72j-4rw9](https://github.com/advisories/GHSA-g9mf-h72j-4rw9), [GHSA-m4v8-wqvr-p9f7](https://github.com/advisories/GHSA-m4v8-wqvr-p9f7), [GHSA-m8rv-5g2x-5cg5](https://github.com/advisories/GHSA-m8rv-5g2x-5cg5), [GHSA-p88m-4jfj-68fv](https://github.com/advisories/GHSA-p88m-4jfj-68fv), [GHSA-r53p-7pc4-xj5r](https://github.com/advisories/GHSA-r53p-7pc4-xj5r), [GHSA-v3r7-h72x-cjcm](https://github.com/advisories/GHSA-v3r7-h72x-cjcm), [GHSA-v9p9-hfj2-hcw8](https://github.com/advisories/GHSA-v9p9-hfj2-hcw8), [GHSA-vrm6-8vpv-qv8q](https://github.com/advisories/GHSA-vrm6-8vpv-qv8q), [GHSA-vxpw-j846-p89q](https://github.com/advisories/GHSA-vxpw-j846-p89q) |
| `unzip-stream` | 0.3.1 | high | [GHSA-6jrj-vc65-c983](https://github.com/advisories/GHSA-6jrj-vc65-c983) |
| `uuid` | 8.3.2 | moderate | [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq) |
| `yaml` | 1.10.2 | moderate | [GHSA-48c2-rrv3-qjmp](https://github.com/advisories/GHSA-48c2-rrv3-qjmp) |

form-data 4.0.0의 critical 경고는 예측 가능한 multipart 경계값 문제입니다. [공식 권고](https://github.com/advisories/GHSA-fjxv-7rqg-78g4)의 4.0.4는 그 문제의 수정 버전이지만, 별도 [CRLF 주입 권고](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx)는 4.0.6 미만에 남습니다. 한 경고의 수정 버전만 바꾸고 전체가 해소됐다고 판단하지 않았습니다.

| 내부 upload-artifact v7.0.0 / 비교한 v7.0.1 패키지 | 설치 버전 | 경고 | 직접 권고 |
|---|---|---|---|
| `brace-expansion` | 1.1.12, 2.0.2, 5.0.3 | high | [GHSA-3jxr-9vmj-r5cp](https://github.com/advisories/GHSA-3jxr-9vmj-r5cp), [GHSA-6j4f-fj2g-mc7p](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p), [GHSA-f886-m6hf-6m8v](https://github.com/advisories/GHSA-f886-m6hf-6m8v), [GHSA-jxxr-4gwj-5jf2](https://github.com/advisories/GHSA-jxxr-4gwj-5jf2), [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg), [GHSA-q2hr-2g5m-vwhr](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr), [GHSA-qhr7-859c-m2p7](https://github.com/advisories/GHSA-qhr7-859c-m2p7), [GHSA-rgw5-rvv9-x895](https://github.com/advisories/GHSA-rgw5-rvv9-x895) |
| `fast-xml-builder` | 1.0.0 | high | [GHSA-5wm8-gmm8-39j9](https://github.com/advisories/GHSA-5wm8-gmm8-39j9) |
| `fast-xml-parser` | 5.4.1 | high | [GHSA-8gc5-j5rx-235r](https://github.com/advisories/GHSA-8gc5-j5rx-235r), [GHSA-gh4j-gqv2-49f6](https://github.com/advisories/GHSA-gh4j-gqv2-49f6), [GHSA-jp2q-39xq-3w4g](https://github.com/advisories/GHSA-jp2q-39xq-3w4g) |
| `lodash` | 4.17.23 | high | [GHSA-f23m-r3pf-42rh](https://github.com/advisories/GHSA-f23m-r3pf-42rh), [GHSA-r5fr-rjxr-66jc](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) |
| `undici` | 6.23.0 | high | [GHSA-2mjp-6q6p-2qxm](https://github.com/advisories/GHSA-2mjp-6q6p-2qxm), [GHSA-35p6-xmwp-9g52](https://github.com/advisories/GHSA-35p6-xmwp-9g52), [GHSA-4992-7rv2-5pvq](https://github.com/advisories/GHSA-4992-7rv2-5pvq), [GHSA-8xcm-r25x-g524](https://github.com/advisories/GHSA-8xcm-r25x-g524), [GHSA-f269-vfmq-vjvj](https://github.com/advisories/GHSA-f269-vfmq-vjvj), [GHSA-g8m3-5g58-fq7m](https://github.com/advisories/GHSA-g8m3-5g58-fq7m), [GHSA-m8rv-5g2x-5cg5](https://github.com/advisories/GHSA-m8rv-5g2x-5cg5), [GHSA-p88m-4jfj-68fv](https://github.com/advisories/GHSA-p88m-4jfj-68fv), [GHSA-r53p-7pc4-xj5r](https://github.com/advisories/GHSA-r53p-7pc4-xj5r), [GHSA-rfgv-xxqx-mfg5](https://github.com/advisories/GHSA-rfgv-xxqx-mfg5), [GHSA-v3r7-h72x-cjcm](https://github.com/advisories/GHSA-v3r7-h72x-cjcm), [GHSA-v9p9-hfj2-hcw8](https://github.com/advisories/GHSA-v9p9-hfj2-hcw8), [GHSA-vrm6-8vpv-qv8q](https://github.com/advisories/GHSA-vrm6-8vpv-qv8q), [GHSA-vxpw-j846-p89q](https://github.com/advisories/GHSA-vxpw-j846-p89q) |

checkout v7.0.1의 `undici 6.27.0`에는 [WebSocket 서비스 거부](https://github.com/advisories/GHSA-rfgv-xxqx-mfg5) 등 경고가 있습니다. checkout main도 high 1개였고 deploy-pages main은 v5.0.1과 같은 커밋이었습니다. upload-artifact 최신 v7.0.1과 main의 커밋도 비교해 같은 high 5개가 남는 것을 확인했습니다.

## 적용한 수정과 남은 차단

CI와 R2 수집 경로는 외부 Action을 쓰지 않습니다. 네이티브 Git으로 고정 공개 저장소의 ref를 읽고 실행 SHA와 일치하는지 확인합니다. credential helper, 훅, 파일 프로토콜과 사용자 Git 설정을 차단합니다. 이 두 경로에서 checkout의 해당 패키지 의존성은 제거됐습니다.

Pages의 build와 deploy는 모두 코드의 `false` 조건으로 잠겨 있어 저장소 변수만 바꿔도 실행되지 않습니다. 잠긴 Action 참조는 배포 구성 초안이며 안전 검토 완료로 표시하지 않습니다. 공식 제공자나 최신 버전이라는 이유로 활성화하지 않았습니다.

이 프로젝트에 `npm overrides`를 추가해도 고정 SHA의 Action에 포함된 실행 번들은 바뀌지 않습니다. 현재 확인한 공식 릴리스 조합에는 경고가 남습니다. 전체가 해소된 공식 번들 또는 별도 검토를 마친 대체 구현과 동작 시험이 필요합니다. 이 작업에서는 런타임 인증 프로토콜을 새로 구현하거나 저장소 쓰기 권한을 추가하는 배포 방식 변경을 결정하지 않았습니다. 원격 실행과 배포는 하지 않았습니다.

## 검사 도구와 근거

[checkout 고정 소스](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/package-lock.json), [deploy-pages 고정 소스](https://github.com/actions/deploy-pages/blob/368f82528645a54fb793d4d04e342629a3f51346/package-lock.json), [업로드 composite](https://github.com/actions/upload-pages-artifact/blob/fc324d3547104276b827a68afc52ff2a11cc49c9/action.yml), [내부 upload-artifact 소스](https://github.com/actions/upload-artifact/blob/bbbca2ddaa5d8feaa63e36b76fdaad77386f024f/package-lock.json), [비교한 최신 업로드 소스](https://github.com/actions/upload-artifact/blob/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/package-lock.json)를 확인했습니다. 이 문서의 각 권고 링크는 해당 패키지의 직접 근거입니다.

검사용 Gitleaks 8.28.0과 actionlint 1.7.7은 공식 릴리스 SHA-256을 확인한 뒤 후보 바깥에서 실행했습니다. R2의 GET과 조건부 PUT 서명은 인공 문자열로 공식 botocore 1.40.50 결과와 비교했습니다. 검사 도구, SDK와 원본 감사 로그는 공개 후보에 포함하지 않습니다. 코드와 데이터의 라이선스 선택, Pages 이용 목적의 약관 검토는 이 취약점 차단과 별개입니다.
