# arp-spoof-refactoring

기존 `arp-spoof` 코드를 구조체 분리, 바이트 오더 정리, 함수 단위 분리를 중심으로 리팩토링하는 프로젝트입니다.

## 목표

- 기존 로직은 유지
- `main()`은 전체 흐름이 보이는 인덱스 형태로 구성
- 패킷 구조체와 네트워크 동작을 역할별로 분리
- 이후 `Flow` 기반 구조로 확장 가능하게 정리

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

## 현재 진행 상황

완료한 항목

- `MacAddress` 분리
- `IpAddress` 분리
- `EthernetHeader` 분리
- `ArpHeader` 분리
- `ArpPacket` 구조 정의
- `Flow` 구조 초안 추가
- `pch` 구성 정리
- ARP 요청/응답 관련 기본 함수 분리 시작

현재 구현된 함수

- `openCaptureHandle()`
- `getMyMacAddress()`
- `getMyIpAddress()`
- `makeArpRequestPacket()`
- `sendArpRequest()`
- `receiveArpReply()`
- `resolveMacAddress()`

## 다음 작업

- `usage()` 및 인자 검사 정리
- `argv`를 `Flow` 목록으로 변환하는 함수 추가
- `main()`을 흐름 중심으로 재구성
- ARP infection packet 생성 함수 추가
- 감염 루프 / relay 루프 분리

## 현재 방향

최종적으로 `main()`은 아래처럼 읽히는 구조를 목표로 합니다.

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
    infectFlows(handle, myMac, myIp, flows);
    relayLoop(handle, myMac, flows);

    pcap_close(handle);
    return 0;
}
