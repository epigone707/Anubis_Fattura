# Malware Analysis of Anubis
Malware Analysis of an Anubis instance.
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
This malware access `https://twitter[.]com/qweqweqwe` and get an ip address which is encoded in a sequence of simplfied Chinese characters.
<p align="center">
    <img src="./screenshots/figure 1.png" />
    <br/>
    <strong>Figure 1.</strong> Visit a twitter account.
</p>

If needed, it will set the C2 server address to be this ip address. Otherwise, it will use the default C2 server `cdnjs.su`.

<p align="center">
    <img src="./screenshots/figure 2.png" />
    <br/>
    <strong>Figure 2.</strong> Set the C2 server address
</p>

### Botnet command
`wocwvy.czyxoxmbauu.slsa.ukhakhcgifofl` sneds POST request to `http://cdnjs[.]su/o1o/a3.php` or `http://cdnjs[.]su/o1o/a4.php` to receive the botnet commands. It then identifies the commands from the C2 server and performs corresponding malicious tasks. The defualt C2 server is `cdnjs.su`, but it can be changed by accessing the twitter account or a specific botnet command. Below gives a brief summary of all commands.

**cmd= |startinj=[str]|endstartinj**  

If the value of `name` is "false" in the pref file `set`, meaning the overlay fake view has been shown(see in the Overlay Attack section), then put key-value pair (`lock_inj`, [str]) in the pref file.

**cmd = Send_GO_SMS|number=[num]|text=[text]**  

It sends SMS message with text=[text] to phone number=[num]. Then, make a POST request to `http://cdnjs[.]su/o1o/a6.php.php` with this SMS info. Finally, set ringer mode to be silent and will not vibrate.

**cmd = nymBePsG0**  

Make a POST request to `http://cdnjs[.]su/o1o/a6.php`. The POST data is the contacts info(country code, number and name) in the phone.

**cmd = GetSWSGO**  

Make a POST request to `http://cdnjs[.]su/o1o/a6.php`. The POST data is the SMS data(sent, inbox, draft) in the phone.

**cmd = GetSWSGO|telbookgotext=[str]|endtextbook**  

Send a SMS message to every contact in the contact list with the text [str]. Then it sends a POST request to `http://cdnjs[.]su/o1o/a6.php` to tell the C2 server whether it succeeds or not.

**cmd = getapps**  

Get a list of the package name of all installed applications. Make a POST request to `http://cdnjs[.]su/o1o/a6.php`. The POST data is that list.

**cmd = getpermissions**  

Get a list of the current state of all permissions i.e. whether they're granted or not. Make a POST request to `http://cdnjs[.]su/o1o/a6.php` with the list.

**cmd = startaccessibility**  

If the value of `startRequest` in preferences file `set` contains "Access=0", change it to "Access=1". Then it opens the accessibility settings and request the accessibility.

**cmd = startpermission**  

If the value of `startRequest` in Preferences "`set`" contains "Perm=0", change it to "Perm=1". Then it will ask the user to allow an app to ignore battery optimizations (that is, put them on the whitelist of apps shown by `ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS`).

**cmd = ALERT|title=[title]|text=[content]**  

Create an alert dialog with title=[title] and content=[content].

**cmd = PUSH|title=[title]|text=[text]|icon=[appname]**  

Post a notification to be shown in the status bar with title=[title] and text=[text]. Get the notification icon from `http://cdnjs[.]su/icon/[appname].png`.

**cmd = startAutoPush|AppName=[appname]|EndAppName**  

Post a notification to be shown in the status bar with title="Urgent message!" and text="Confirm your account". It will identify the language setting of the phone and show the text in different language. The notification icon is got from `http://cdnjs[.]su/icon/[appname].png`.

**cmd = RequestPermissionInj**  

Request Usage access, which allows this malware to track what other apps you're using and how often, as well as your carrier, language settings, and other details.

**cmd = RequestPermissionGPS**  

Request gps permission.

**cmd = |ussd=[USSD]]|endUssD**  

Make a USSD call to [USSD] and set the ringer mode to be silent and not vibrate. Then make a POST request to `http://cdnjs[.]su/o1o/a6.php` to tell the server that it has finished the call.

**cmd= |sockshost=[host]|user=[user]|pass=[pass]|port=[port]|endssh**  

This command starts a SOCKS5 proxy by doing following tasks:
1. Create a thread(denoted as thread 0) which creates a server socket and bound to the loacl port 34500. Once a client connects, create and start a new thread(denoted as thread 1).
<p align="center">
    <img src="./screenshots/figure 3.png" />
    <br/>
    <strong>Figure 3.</strong> Create a server socket and start a new thread.
</p>
2. Thread 1 sends a register message to the client. The client could be the threat actor.
3. Thread 1 receive the destination ip address and port nunmber from the client.
<p align="center">
    <img src="./screenshots/figure 4.png" />
    <br/>
    <strong>Figure 4.</strong> Thread 1 sends register msg and receive the ip and port.
</p>
4. Thread 1 send a response msg to the client.
5. Thread 1 create a new socket that connect to the destination ip and port. It then constantly forwards all data from the client to the destination. It also create a new thread(denoted as thread 2) to forward the data from the destination to the client. 
<p align="center">
    <img src="./screenshots/figure 5.png" />
    <br/>
    <strong>Figure 5.</strong> Thread 1 constantly forward the traffic between the client and the destination server.
</p>
6. After thread 1 starts, thread 0 loads and invokes a method `apps.com.app.utils.startSocks` with params: (context, [host], [user], [pass], [port]). About how to find the source code of this method, see the [Header](#About-Finding-the-Loaded-Class) section.
7. Thread 0 also constantly sends a POST request to `http://cdnjs[.]su/o1o/a6.php` with the proxy server info every 8 seconds. The info contains an SSH local port forwarding command, which is used by the client(threat actor). 
<p align="center">
    <img src="./screenshots/figure 6.png" />
    <br/>
    <strong>Figure 6.</strong> Thread 0 invokes a method and sends POST request.
</p>
<p align="center">
    <img src="./screenshots/figure 7.png" />
    <br/>
    <strong>Figure 7.</strong> Invokes the method apps.com.app.utils.startSocks.
</p>
<p align="center">
    <img src="./screenshots/figure 8.png" />
    <br/>
    <strong>Figure 8.</strong> Summary of the construction.
</p>
**cmd = stopsocks5**  

Stop the SOCKS5 proxy by change the value of `socks` to "stop" in the preference file `set`

**cmd = |spam=[text]|endspam**  

Make a POST request to  `http://cdnjs[.]su/o1o/a15.php` to get the target phone numbers and send spam SMS message to those numbers.

**cmd = |recordsound=[seconds]]|endrecord**  

Record sound for [seconds] seconds.

**cmd = |replaceurl=[newurl]|endurl**  

Change the value of `url` and `urls` to [newurl] in the preference file `set`. This command changes the C2 server address that is stored in local storage.

**cmd = |startapplication=[app]|endapp**  

Start the [app] application.

**cmd = killBot**  

Clear the value of `url`, `urls` and `urlInj` in the preference file `set`. Then stop the wfveenegvz service.

**cmd = getkeylogger**  

Read the file `keys.log`, which is a log file of the recorded keystrokes. Then make a POST request to `http://cdnjs[.]su/o1o/a12.php`. The POST data is the unique bot id and the content of the file `keys.log`.

The keylogger is implemented in `wocwvy.czyxoxmbauu.slsa.egxltnv `accessibility service. The onAccessibilityEvent function first gets the package name of the accessibilityEvent.
<p align="center">
    <img src="./screenshots/figure 9.png" />
    <br/>
    <strong>Figure 9.</strong> Get the package name.
</p>
Then it identifies the type of the accessibilityEvent. If it is `TYPE_VIEW_CLICKED`(click event), it stores the keystrokes info and corresponding timestamp in the file `keys.log`. Similarly, it also stores the infomation of view focus event and view text change event.
<p align="center">
    <img src="./screenshots/figure 10.png" />
    <br/>
    <strong>Figure 10.</strong> The implementation of the keylogger.
</p>

**cmd = |startrat=[null]|endrat=[websocket]|endurl**  

The "rat" in this command means Remote Access Trojan(RAT).
It send a POST request to `[websocket]/o1o/a2.php` and get the response, the post data is the bot id. The response is the RAT command.

- **RAT_command = opendir:[path]**  
Get a list of files and folders that is in the local path [path]. Send a POST request to [websocket]/o1o/a2.php. The data is the list.
- **RAT_command = downloadfile:[file]**  
Send a POST to `[websocket]/o1o/a1.php`, the POST data is the file [file]. Send a POST to `[websocket]/o1o/a2.php` to tell the server that the task is finished.
- **RAT_command = deletefilefolder:[file]**  
Delete the file [file]. Send a POST to `[websocket]/o1o/a2.php` to tell the server that the task is finished.
- **RAT_command = startscreenVNC**  
Start a virtual network computing (VNC) that can see the screen of the victim's device. This functionality is implemented in `wocwvy.czyxoxmbauu.slsa.oyqwzkyy.qvhy.jkeggfql` service. It use the API `android.media.projection.MediaProjection` to take a screenshot of the screen and sends it to `[websocket]/o1o/a1.php` via a POST request for every 0.5 second.
<p align="center">
    <img src="./screenshots/figure 11.png" />
    <br/>
    <strong>Figure 11.</strong> Media projection.
</p>
<p align="center">
    <img src="./screenshots/figure 12.png" />
    <br/>
    <strong>Figure 12.</strong> Send the screenshot.
</p>
- **RAT_command = stopscreenVNC**  
Stop the VNC.
- **RAT_command = startsound**  
Start to record the sound.
- **RAT_command = stopsound**  
Stop the sound recording.
- **RAT_command = startforegroundsound**  
Same to startsound, but will show a notification with text "Update Google Play Service".

**cmd = startforward=[number]|endforward**

Set ringer mode to be silent and will not vibrate. Make a call to [number]

**cmd = stopforward**

Stop the call.

**cmd = |openbrowser=[url]|endbrowser**

Open the [url] in web browser.

**cmd = |openactivity=[url]|endactivity**

Open the [url] by calling `webView.loadUrl()`.

**cmd = |cryptokey=[key]:[lock_amount]:[lock_btc]|endcrypt**

Encrypt files stored in the device and SD card by using the key. The encrpyted files have the .AnubisCrypt file extension. Then it deletes the original files. After this has been done, the victim user can no longer access those files. This is a feature of ransomware.
<p align="center">
    <img src="./screenshots/figure 13.png" />
    <br/>
    <strong>Figure 13.</strong> Target directories.
</p>

**cmd = |decryptokey=[key]|enddecrypt**

Decrypt those previously encrypted files.
<p align="center">
    <img src="./screenshots/figure 14.png" />
    <br/>
    <strong>Figure 14.</strong> Encrypt and decrypt.
</p>

**cmd = getIP**

Access `http://en.utrace.de` to get the ip address of the victim device. Make a POST request to `http://cdnjs[.]su/o1o/a6.php`, the POST data is the ip info.


### Prevent Uninstall

The `wocwvy.czyxoxmbauu.slsa.egxltnv` accessibility service prevents the malware from being uninstalled. 
<p align="center">
    <img src="./screenshots/figure 15.png" />
    <br/>
    <strong>Figure 15.</strong> Detect that the user is trying to uninstall the malware.
</p>
<p align="center">
    <img src="./screenshots/figure 16.png" />
    <br/>
    <strong>Figure 16.</strong> Go back to the home screen.
</p>

### Overlay Attack
Similar to Timpdoor, this malware identifies the installed banking applications in the device. Once one of those banking app is running by the user, it plays an overlay attack. Below is how it actually conducts the attack.

After the malware receives **cmd = PUSH|title=[title]|text=[text]|icon=[appname]** from the server, it will store the string appname as the value of `str_push_fish` in the preference file `set`. This key-value pair will then be used in `wocwvy.czyxoxmbauu.slsa.ncec.ozkgyjpxtyxajmm` to retreive the fake webview of the corresponding banking application from the C2 server and show it to the victim user.
<p align="center">
    <img src="./screenshots/figure real17.png" />
    <br/>
    <strong>Figure 17.</strong> Overlay attack.
</p>

### Evade Analysis Environment
The `wocwvy.czyxoxmbauu.slsa.blyvffs` sevice used motion sensor to determine whether it is running in an analysis environment. This is a feature of Anubis.
<p align="center">
    <img src="./screenshots/figure 17.png" />
    <br/>
    <strong>Figure 18.</strong> Listen to the change of the motion data.
</p>

## Dynamic Traffic Analysis

I install the app in Android studio AVD(Android 8.1, API 27) and use Fiddler to capture the traffic of this app. 

After clicking its icon, it asks the user to give it permissions. If granted, it hides its icon. The user can't open the app infomation page in setting, thus can't uninstall it. The Prevent Uninstall section describes how this functionality works.

According to Fiddler, it keeps sending a POST request to `http://cdnjs[.]su/o1o/a16.php` and try to connect to `http://twitter.com:443`, which matches the static analysis result.
<p align="center">
    <img src="./screenshots/figure 18.png" />
    <br/>
    <strong>Figure 19.</strong> Captured traffic.
</p>

cdnjs is a free and open-source software content delivery network (CDN) hosted by Cloudflare. The malware fails to find `cdnjs.su` because this C2 server has been turned down.

## About Twitter Channel

According to these two reports, the Anubis malware connects to twitter in order to fetch the address of its C2 server from a public twitter account. 
- https://news.sophos.com/en-us/2019/05/01/how-anubis-uses-telegram-and-chinese-characters-to-phone-home/
- https://www.phishlabs.com/bankbot-anubis-telegram-chinese-c2/

## <a id="my-header"></a>About Finding the Loaded Class
This malware loads the class `apps.com.app.utils` and invokes the `startSocks` method when it starts a SOCKS5 proxy. This article gives an introduction of how to hook the `DexClassLoader` and find the dynamically loaded classes.
- https://pentest.blog/n-ways-to-unpack-mobile-malware/






