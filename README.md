# network_security_codes
### 과제 목적

PCAP API를 활용하여 TCP 패킷을 실시간으로 캡쳐하고 

Ethernet, IP, TCP Header, Message의 정보를 출력하는 프로그램을 구현한다.


---


### 구현 설명


**사용 기술**

- 언어: C
- 사용 라이브러리: libpcap
- 파일 구성: print_packet.c, header.h
    - struct 구현: ethheader, ipheader, tcpheader


---


### 분석 환경

- NIC: enp0s1
- 테스트 명령: `curl -v http://example.com`
