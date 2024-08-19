# arp-spoof
## Basic info
attacker : BestITWorld
sender(victim) : Apple_71

### network 1

<img src = "https://github.com/user-attachments/assets/ac675d93-6dfd-4a8f-a635-b5302e8cc8be" width="400" height="400">

### network 2
<img src = "https://github.com/user-attachments/assets/82173df7-de00-4c19-b6a3-4a5ed3e4c8cf" width="400" height="400">
<img src = "https://github.com/user-attachments/assets/622c3c0d-ef1b-41d0-832a-2c67d063ff0b" width="400" height="400">

## Victim
### Victim(sender) ifconfig
<img width="554" alt="스크린샷 2024-08-19 오전 9 04 13" src="https://github.com/user-attachments/assets/ad4ad91e-c086-4343-a7dd-358abe0cace5">

### Victim(sender) spoofed arp table
<img width="577" alt="스크린샷 2024-08-19 오전 9 03 47" src="https://github.com/user-attachments/assets/81accd28-bf75-4564-8261-23885607f489">

### Ping
<img width="495" alt="스크린샷 2024-08-19 오전 9 02 35" src="https://github.com/user-attachments/assets/f2c6e280-e40b-442e-93a4-c280903d6dbc">

## Result
### Arp
![arp](https://github.com/user-attachments/assets/35e85cad-9a8d-4f74-a8c6-39d3ebb5ef37)
초기 sender와 target의 MAC 주소를 알아내기 위한 ARP + arp recover 탐지한 후 재감염 ARP + 지속적으로(5초) 감염시키는 ARP

### Ping
아래 명령어를 실행시킨 결과
```
ping gilgil.net
```
![ping](https://github.com/user-attachments/assets/e9f83bdf-3698-4806-a350-630a7e9368b5)
ping을 4개 단위로 보면 request가 2개(relay), reply가 2개(relay)가 제대로 캡쳐 됨.



### Tcp(Http)
아래 사이트로 접속한 결과 <br>
http://gilgil.net
![tcp](https://github.com/user-attachments/assets/65bc1cf3-fe12-456d-a281-d4ae2e5d4954)
tcp 연결은 relay 되어 2개 단위로 동일한 패킷이 제대로 캡쳐가 됨.
http는 한 개만 캡쳐됨.
