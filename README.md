# anubis_Fattura
Malware Analysis
## Application metadata
- Application Name: Fattura
- Package Name: wocwvy.czyxoxmbauu.slsa
- Main Activity: wocwvy.czyxoxmbauu.slsa.ncec.myvbo
- Target SDK: 27
- Min SDK: 15
- Android Version Name: 1.0
- Android Version Code: 1
- SHA256: a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc

## Permissions 
The application has dangerous permissions:
- android.permission.ACCESS_FINE_LOCATION
- android.permission.GET_TASKS
- android.permission.RECEIVE_SMS
- android.permission.READ_SMS
- android.permission.WRITE_SMS
- android.permission.SYSTEM_ALERT_WINDOW
- android.permission.CALL_PHONE
- android.permission.SEND_SMS
- android.permission.WRITE_EXTERNAL_STORAGE
- android.permission.READ_EXTERNAL_STORAGE
- android.permission.RECORD_AUDIO
- android.permission.READ_CONTACTS
- android.permission.READ_PHONE_STATE

It also has a signature permission:

- android.permission.PACKAGE_USAGE_STATS

## Static Analysis

### Twitter channel
This malware access <https://twitter[.]com/qweqweqwe> and get an ip address which is encoded in a sequence of simplfied Chinese characters.