# arp-spoof-refactoring

기존 `arp-spoof` 코드를 구조체 분리, 바이트 오더 정리, 함수 단위 분리를 중심으로 리팩토링하는 프로젝트입니다.

## 목표

- 기존 로직은 유지
- `main()`은 전체 흐름이 보이는 인덱스 형태로 구성
- 패킷 구조체와 네트워크 동작을 역할별로 분리
- `Flow` 단위로 sender / target 관계를 관리
- 이후 유지보수와 테스트가 쉬운 구조로 정리

## 코드 컨벤션

| 대상 | 규칙 | 예시 |
|---|---|---|
| 지역 변수 | `camelCase` | `packetSize`, `sourceAddress` |
| 매개변수 | `camelCase` | `buffer`, `timeoutMs` |
| 클래스 멤버 | `m_` + `camelCase` | `m_socket`, `m_receiveBuffer` |
| 전역 변수 | 가급적 사용하지 않음, 필요 시 `g_` | `g_packetCount` |
| 상수 | `k` + `PascalCase` | `kMaxPacketSize` |
| 함수 | `camelCase` | `sendPacket()`, `parseHeader()` |
| 클래스/구조체 | `PascalCase` | `PacketHeader`, `PacketReceiver` |
| enum 타입 | `PascalCase` | `PacketType` |
| enum 값 | `PascalCase` | `PacketType::Heartbeat` |
| bool 변수 | 질문처럼 읽히는 이름 | `isConnected`, `hasHeader` |
| 포인터 | 별도 접두사 없이 의미 중심 | `packetData`, `socketHandle` |

## 바이트 오더 기준

현재 리팩토링 기준은 다음과 같이 통일합니다.

- `MacAddress`
  - raw byte 저장
  - 별도 엔디안 변환 없음

- `IpAddress`
  - 내부 저장은 `network byte order`
  - 숫자로 사용할 때만 `hostOrder()`로 변환

- `EthernetHeader`, `ArpHeader`
  - 패킷 구조체이므로 내부 필드는 `network byte order`
  - `uint16_t` 필드는 getter에서 `ntohs()`로 해석

## 현재 구현 상태

완료한 항목

- `MacAddress` 분리
- `IpAddress` 분리
- `EthernetHeader` 분리
- `ArpHeader` 분리
- `ArpPacket` 구조 정의
- `Flow` 구조 정의
- `pch` 구성 정리
- ARP request / reply 생성 로직 분리
- sender / target MAC 해석 로직 분리
- 감염 패킷 전송 로직 분리
- relay loop 기본 구조 구현
- ARP 패킷 감지 후 재감염 기본 처리 추가

## 프로그램 흐름

```text
parse arguments
    ->
parse flows
    ->
open capture handle
    ->
get my mac / ip
    ->
resolve sender / target mac addresses
    ->
send arp infection packets
    ->
relay ipv4 packets
    ->
reinfect when arp packets are observed
```

## 메인 워크플로우

최종적으로 `main()`은 아래 흐름으로 동작합니다.

```cpp
int main(int argc, char* argv[])
{
    validateArguments(argc, argv);
    auto flows = parseFlows(argc, argv);

    const char* interfaceName = argv[1];

    pcap_t* handle = openCaptureHandle(interfaceName);
    MacAddress myMac = getMyMacAddress(interfaceName);
    IpAddress myIp = getMyIpAddress(interfaceName);

    resolveFlowMacAddresses(handle, myMac, myIp, flows);
    infectFlows(handle, myMac, flows);
    relayLoop(handle, myMac, flows);

    pcap_close(handle);
    return 0;
}
```

## 함수 설명

### 초기화 / 환경 준비

- `usage()`
  - 프로그램 사용법 출력

- `openCaptureHandle()`
  - 지정한 인터페이스로 `pcap` 캡처 핸들 생성

- `getMyMacAddress()`
  - 현재 인터페이스의 MAC 주소 조회

- `getMyIpAddress()`
  - 현재 인터페이스의 IP 주소 조회

### 흐름 구성

- `parseFlows()`
  - 명령행 인자를 `Flow` 목록으로 변환
  - 입력 형식: `<sender ip> <target ip>` 쌍 반복

- `resolveFlowMacAddresses()`
  - 각 `Flow`의 `senderMac`, `targetMac` 채움

### ARP 해석

- `makeArpRequestPacket()`
  - ARP request 패킷 생성

- `sendArpRequest()`
  - ARP request 전송

- `receiveArpReply()`
  - 대상 IP의 ARP reply를 기다렸다가 MAC 주소 반환

- `resolveMacAddress()`
  - request 생성 / 전송 / reply 수신을 묶어 IP로 MAC 주소 조회

### 감염

- `makeArpReplyPacket()`
  - sender를 속이기 위한 forged ARP reply 생성

- `infectFlow()`
  - 하나의 `Flow`에 대해 감염 패킷 전송

- `infectFlows()`
  - 모든 `Flow`에 대해 감염 수행

### 릴레이 / 유지

- `isFromSenderToTarget()`
  - 수신 패킷이 sender에서 온 것인지 판별

- `isFromTargetToSender()`
  - 수신 패킷이 target에서 온 것인지 판별

- `relayPacket()`
  - 목적지 MAC을 바꿔 패킷 재전송

- `handleArpPacket()`
  - ARP 패킷 감지 시 재감염 처리

- `relayLoop()`
  - IPv4 패킷 릴레이와 ARP 기반 재감염을 반복 수행

## 실행 예시

단방향 흐름:

```bash
arp-spoof wlan0 192.168.0.10 192.168.0.1
```

양방향 흐름:

```bash
arp-spoof wlan0 192.168.0.10 192.168.0.1 192.168.0.1 192.168.0.10
```

## 현재 한계 / 메모

- 현재 양방향 감염은 `A B B A` 형태로 인자를 두 쌍 넣어 처리
- `MacAddress` 비교 연산자 등 일부 정리 작업은 이후 리팩토링 대상
