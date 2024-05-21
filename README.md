
# syn패킷 감지및 syn flood 공격 방지 스크립트
해당 스크립트는 리눅스 시스템에서 동작하도록 설계되었습니다.  
스크립트를 컴파일 하기 전에 python3인터프린터가 필요합니다.  
리눅스 cli에서

> sudo apt install python3

를 입력하여 python 인터프린터를 설치하거나
인터넷 브라우저를 이용하여 python 인터프린터를 설치해야 합니다.

syndetector.py스크립트는 단위시간동안 서버에 들어오는 syn패킷의 개수를 측정한 후  
그에 따라 서버의 백로그 크기, synack 재전송 횟수, syncookie 활성화 여부를 변경합니다. 
  
config.ini에서는 syndetector.py에서 사용되는 변수들을 사용자가 임의로 설정할 수 있습니다.  
변수들의 자세한 내용은 config.ini파일을 참고 바랍니다.  



</br>
PrintSystemStatus.py파일은  
일정 주기마다 현재 서버의 백로그 크기, synack재전송 회수, syncookie 활성화 여부를 출력합니다.  
