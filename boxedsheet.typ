#import "lib.typ": *

#set text(font: "Roboto")
#set text(lang: "en", //TODO LANG DE/EN
    region: "gb")

#show figure: set figure(supplement: [])


#let author = "Stanislas Laurent"
#let title = "SWS"

#show: boxedsheet.with(
  title: title,
  authors: author,
  title-align: left,
  title-number: true,
  homepage: "lauresta",
  title-delta: 2pt,
  scaling-size: false,
  font-size: 5.5pt,
  line-skip: 5.5pt,
  x-margin: 10pt,
  y-margin: 20pt,
  num-columns: 4,
  column-gutter: 2pt,
  numbered-units: false,
)

= Basics
#concept-block(body: [
  #inline("CIA")
  - *Confidentiality*: Sensitive data must be protected from unauthorised read access 
  - *Integrity*: Data and systems must be protected from unauthorised modification
  - *Availability*: The information must be available when it is needed
  #inline("Defs")
  - *Vulnerability:* Defect (bug or flaw) that attacker can exploit
  - *Threat:* Possible danger that might exploit a vulne. Intentional: attacker working on exploit. Accidental: server room fire.
  - *Threat agent:* Attacker
  - *Threat action:* Actual attack procedure
  - *Exploit*: Actual attack that takes advantage of (exploits) the vulne (e.g. malware program)
  - *Asset*: Anything (hardware, software, data,...) that is of value to an organisation (and therefore also to a potential attacker)
  - *Risk*: Criticality of a specific threat or vulnerability. _Measured in terms of a combination of the probability of a successful attack and its consequences: risk = probability × impact_
  - *Countermeasure*:  An action, device, process or technique that reduces a risk
  #inline("Malware types")
  - *Malware*: malicious software used to disrupt computer operation, gather sensitive information, or gain access to private computer systems
  - *Virus*: Spreads by inserting copies of itself into executable programs or documents (hosts), usually requires user interaction to spread
  - *Worm*: Malware, that spreads and executes on its own, without requiring a host program (as is the case with viruses). Scans for other sys, find vulne, infect new sys
  - *Trojan*: impostors – files or programs that claim to be something desirable but, in fact, are malicious. Do not replicate themselves. 
  - *Drive-by download*: Browser/plugin vulnerability → auto-execute malicious code from compromised site
  - New targets: custom web apps, ransomware
  #inline("Defect types")
  - *Bug*: Localised problem introduced by *implementation*, simple fix. Discovered by _code review_.
    - `gets()` -> `fgets()`, use prepared statements
  - *Design flaw*: Architectural problem. Discovered by _threat modelling_.
    - Plaintext pws without hashing or salting
    - Client-only validation
    - HTTP login (no HTTPS)
  - ~50/50 split → design review matters as much as code review!
   #inline("Reactive countermeasures")
  - *Penetrate and Patch*: patch issues as they are discovered, widely used. _But: time until patch, time for users to install, might add new vulnes_
  - *Network Security Devices*: blocks attacks, e.g. WAF (web app firewall), IPS (intrusion prevent sys). Can't recognise all attacks.
  #inline("Proactive countermeasures")
  - *Secure Development Life-cycle*: Only valid approach, think like an attacker and test security at stages of development. _But: not 100%, still need reactive approaches_
])

= SDL (Secure Dev Life-cycle)
#concept-block(body: [
  #inline("Security activities", padding: false)
  #image("sdl.png", width: 80%)
  1. *Security requs*: based on functional requs. Must be clear and have no technical details. _(e.g. provide credit card → use crypto protected channel)_. Additional requs produced from thread model. activity. 
  2. *Thread modelling (50%)*: identify security design flaws based on the security requirements or 
    security controls that have already been defined.
    1. Imagine you're an attacker looking at the system
    2. Identify possible threats and deduce vulnerabilities _eg. attacker could set fire to serve room → no data redundance_
    3. Define more security requs. based on vulnes
  3. *Secu design & controls*; Based on secu requs, choose secu mechanism. _eg: strong user auth requ → use 2FA with pw+biometric | prevent buffer overflow → use secure functions and compiler+OS secu features | ACM must be used → use Spring Security's role-based feature | separate admin features as much as poss → sep. web app for users and admins and require VPN_
  4. *Secure coding (50%)*: being careful when writing, implement secu controls properly, avoid secu bugs, use secu checklists, compiler checks & warnings
  5. *Code review*: inspect code to detect secu bugs, use auto. code analysis tool + manual review
  6. *Pen. testing*: Play as attacker and hack sys, discover undiscovered secu requs and secu bugs. Use automated tools, + human (much better)
  7. *Secu ops*: patch updates, sys & net monitoring, data backups, learn abt attempted attacks and detect successful ones
  #inline("Misc")
  - *Security risk analysis*: estimate risk of problems uncovered by 7 activities, and decide whether to act
  - SDL can be adopted incrementally. The earlier the better (lower fixing costs, avoid "quick symptom patches")
  - Early activities *prevent* defects, late activities *detect* them
  - Fix early = 10-100x cheaper than fixing late
])

= Secu design/controls & code secu (SDL 3 & 4)

#concept-block(body: [
  #inline("7 (+1) Kingdoms categorisation")
  1. *Input validation & representation*: input data processed without being checked/sanitised. Made hard by encoding (use valid characters that bypass validation).
    1. Buffer overflow: exceed functions buffer, modifying unrelated memory
    2. Injection attacks: execute system commands on the server
    3. Cross-site scripting: execute JS code in the user's browser (e.g. steal stored pws)
    4. Path traversal: access files on the target system _http://www.host.com/../../etc/passwords _
  2. *API abuse*: API is used in a way not foreseen by developer
    1. Dangerous functions called by API _eg gets in C (copies all input from STDIN to the buffer without checking size)_
    2. Unchecked returned values _returns null, causes server or client crashes_
    3. Wrong assumptions: _server accessible only by hostname "alice.zhaw.ch". Dev uses getHostNames to convert IP to hostname and check if allowed. But DNS can be spoofed. Dev assumed DNS is safe._
  3. *Secu features*: reimplement your own, or misuse provided ones. _bad pseudo-random, incomplete access control, weak encryption (MD5, DES, RC4...)_
  4. *Time & state*: issues due to parallelisation of tasks across multiple system. _eg: deadlocks, TOCTOU file access race condition, reuse of session IDs, timing auth attacks_
  5. *Error handling*: mismanagement of the double control flow and data
    1. Internal data leakage: error message contains sensitive info (e.g. stack trace)
    2. Empty/broad catch block: program could crash bc error unhandled, or the borad catch could suppress errors in inherited classes _\//TODO handle error_
  6. *Code quali*:
    1. Mem leak: mem never freed, program runs out of mem _filling StringBuffer_
    2. Unrelease resource: same as mem
    4. Deprecated code: dead lib code that isnt patched _C's gets()_
    5. Null deref: can't be derefed, program crashes
    6. Uninit var: value can be unpredictable
  7. *Encapsulation*: Poor boundaries between users, programs and data
    1. Sensitive data in hidden form fields: not visible, but can still be accessed
    2. Cross-site request forgery: attacker makes HTTP requests into users' authenticated sessions, due to lack of user-specific auth (token...)
  8. *(\*) Env*: Stuff that is used to run our code, but not directly controlled by us
    1. Insecure compiler opti: dev overwrites sensi data, but compiler removes the write op to optimise code
    2. Too short session IDs in web app framework
])

= Web app attacks (SDL 5 & 6)
#concept-block(body: [
  Many web apps, security low and critical data (banking, e-commerce...)
  OWASP: Top Ten, Testing Guide, App Secu Verif Standard, WebGoat (bad app example)
  #image("webappsbasic.png")
  #inline("Injection attacks")
  #subinline("SQL")
  1. Test for vulne:
    - *Testing*: Insert `'` → SQL error (HTTP 500, different response) = vulnerable
    - *Time-based*: ```sql SLEEP(5)``` causes delay if vulnerable
    - *Boolean-based*: See if diff. response for `true`/`false` conditions (e.g., ```sql ' AND 1=1--``` vs ```sql ' AND 1=2--```)
  2. Get db schemas
    - *Getting table names*: ```sql SELECT * FROM user_data WHERE last_name = Smith' UNION SELECT 1,TABLE_NAME,3,4,5,6,7 FROM INFORMATION_SCHEMA.SYSTEM_TABLES--``` 
      1. We assume `user_data` has 7 columns, all `int` except the 2nd one which is `string`
      2. We set the `UNION` query so that all columns but the 2nd are string literals (arbitrary numbers)
      3. We set the 2nd column to `TABLE_NAME` and query the `INFORMATION_SCHEMA.SYSTEM_COLUMNS`
      4. Second column contains one table name per row
    - *Getting column names of a table*: ```sql SELECT * FROM user_data WHERE last_name = Smith' UNION SELECT 1,COLUMN_NAME,3,4,5,6,7 FROM INFORMATION_SCHEMA.SYSTEM_COLUMNS WHERE TABLE_NAME = 'EMPLOYEE'--```
      3. We set the 2nd column to `COLUMN_NAME` and query the `INFORMATION_SCHEMA.SYSTEM_COLUMNS` for table `EMPLOYEES`
      4. Second column contains one column name per row
  - Exploit:
    - *Tautology attack*: ```sql ' OR ''='``` (`OR` is evaluated after `AND`) or ```sql ' OR 1=1```
    - *UNION attack*:
      1. *Find column count*: Try ```sql ' UNION SELECT 1 -- ```, ```sql ' UNION SELECT 1,2 -- ```, etc. until no error. Or ```sql ' ORDER BY 4 -- ``` (if 4 fails, there are 3 columns)
      2. *Extract data*: ```sql ' UNION SELECT col1,CAST(col2 AS INT),... FROM table--``` (columns must match count AND types).
    - Insertion attacks (here in password field): ```sql userpw'), ('admin', 'Superuser', 'adminpw')--```
    - Update attack: ```sql ; UPDATE employee SET password = 'foo'-```
    - If multiple params in query: ```sql -- ``` to make rest of query a comment. In MySQL the trailing space is required.
    - Use ```sql ;``` to execute separate queries, only if server uses `executeBatch()`
    - If app only reads first row: use `LIMIT offset,1` to select which row (e.g., ```sql ' OR 1=1 LIMIT 4,1#``` → (4+1)th row, read 1 row only)
  - *sqlmap (Automation)*:
    - *Check for vuln*: ```sh sqlmap -r request.txt -p account_name```
      - `-r request.txt`: HTTP request recorded in file
      - `-p account_name`: Specify target parameter
    - *List schemas/databases*: ```sh sqlmap -r request.txt --dbs```
    - *List tables*: ```sh sqlmap -r request.txt -D PUBLIC --tables```
      - `-D PUBLIC`: Specify the schema/database
    - *Dump table content*: ```sh sqlmap -r request.txt -D PUBLIC -T EMPLOYEE --dump```
      - `-T EMPLOYEE`: Specify the table
  - *Countermeasures:* Prepared statements, all inputs are pre-compiled and special chars are escaped (```java $sth = prepare("SELECT id FROM users WHERE name=? AND pass=?"); execute($sth, $name, $pass);``` yields ```sql SELECT id FROM users WHERE name='\' OR \'\'=\'' AND pass='\' OR \'\'=\'';```)
  #subinline("OS Cmd")
  - Exploit: `; cat /etc/shadow`
  - Java `Runtime.exec()` instead of `FileReader`/`FileInputStream`/`ProcessBuilder`, PHP `system()`
  - *Test*: Analyse REST request, e.g. `HelpFile` field. Append `"` after filename and check for err. Append `; ipconfig`/` & ipconfig` (nix/msft). Might need to prepend `"` if app uses file path.
  - *Counter*: 
    - use IO classes instead of OS runtime
    - use character whitelisting (ban quotes...)
    - run process with minimal privieges
  - *Linux Permissions*: `-rwxr-xr-x 1 root root`
    #table(
      columns: (auto, auto, auto, auto),
      inset: 6pt,
      align: (center, center, left, center),
      [*Part*], [*Octal*], [*Role*], [*Octal vals*],
      [-], [-], [File Type], [Regular File],
      [rwx], [*7*], [Owner (root)], [$4+2+1$],
      [r-x], [*5*], [Group (root)], [$4+0+1$],
      [r-x], [*5*], [Others], [$4+0+1$],
    )
    `755`: everyone can execute, but only `root` can modify.
    #subinline("JSON/XML")
  - *JSON*: app inserts data inside of JSON -> you can overwrite previous keys, since the last occurrence matters. Insert: `myPassword","admin":"true`
  - Same principle for *XML*
  - *Counter:* blacklist curly brackets, special chars
  \
  \
  #subinline("XML External Entitiy Injection")
  Attacker makes a manual POST request with a special XML body:
  ```xml
<?xml version="1.0"?>
<!DOCTYPE query [
  <!ENTITY attack SYSTEM "file:///etc/passwd">
]>
<comment>
  <text>&attack;</text>
</comment>
  ```
The app will display the password file content instead as the comment text.
- *Counter:* blacklist < and >, disabled ext. entities in XML parser, use JSOn instead

#inline("Auth & session")
#subinline("Broken Authentication")
- *Username enumeration*: Find valid usernames before brute-forcing
  - Login behaves differently for existing/non-existing users (message, response time)
  - Account creation: app complains if username already taken
  - *Counter*: Vague error messages ("Login failed"), CAPTCHA on account creation
- *Online brute-force*:
  - *Prerequisite*: Unlimited login attempts without account lockout
  - Burp Intruder: Capture login, mark username + password, remove Cookie header, *Cluster bomb* attack
  - Find valid credentials: Look for *outliers* (different status code or response length)
  - *Counter*: Rate limiting (e.g., 60s delay after 3 failures). Do NOT lock accounts → enables DoS (Denial of Service). Enforce password quality + check against common password lists
- *Pw reset*: 
  1. Attck calls Amazon and usurps using security quest (name, email and billing address) to log-in
  2. Adds credit card
  3. Calls again, then adds 2nd email
  4. Uses 2nd email to pw reset, sets own pw \
  *Counter:* no reset pw feat and force phone call, use hard security questions, issue temp new pw, issue unique pw reset lin
#subinline("Broken session mngmt")
- Attacker gets session ID (guess, exposed, timeout issue, bad rotation, fixation...)
- Session ID: random, used to ID user, generated when logged in
- *Session fixation*: Attacker tricks the user into using the web app with their (attack) session ID, e.g. by sending a URL with the session ID. Then attacker waits for user to log in, add credit card... \
  *Counter:* long random 128bit UIDs, change ID for each login, use cookies not URL, use session timeouts (10min)

  #inline("XSS (cross-site scripting)")
  Inject own JS code that is executed in other user's browser, without having to modify server code  
  #subinline("Stored (persist)")
  Attacker places attack script directly as normal data in the web app (e.g. as a post comment). When user views it, browser executes the `script` tag.
  #subinline("Reflected (non-persist)")
  1. Make user click a link that makes server send back malicious script (e.g. as search query result: `http://www.xyz.com/search.asp?searchString=<script>ATTACK CODE</script>"`)
  2. App displays "Search results for ...". The script tag is added to DOM and executed, not displayed.
  - *Note*: both require poor serve code (no sanitation), storing+displaying of data  
  - *Test*: `<script>alert("XSS worked");</script>`
  #image("xssjack.png", width: 90%)
  Can make form submission *automatic* by putting `send_postdata()` in a script tag \
  *Counters to reflected:* 
    - replace `<script>alert("XSS");</script>` with `&lt;script&gt;alert(&quot;XSS&quot;);&lt;/script&gt;`
    - *XSS Auditor* detects that the JS code returned by server is the same as the one sent by the browser's previous REST request (*not in Firefox*). Can be bypassed with a local proxy.  (diff emitting address)
    - CSP: specify which web content can be loaded from which locations (domains or hosts). ` Content-Security-Policy: default-src 'self'; img-src *; media-src media1.com media2.com; script-src scripts.supersecure.com`: same, imgs from anywhere, audio/video from media1 and media2, script from scripts.supersecure.com.
  #subinline("DOM-based XSS")
  Server not involved. 
  - Variant 1 (`unescape`):
    0. App displays `document.location.href` to the user, *using `unescape()`*
    1. Attacker makes user click `ubuntu.test/attackdemo/general/DOMbased_XSS1.html#<script>alert("XSS");</script>`
    2. App adds script to DOM, which is executed but not displayed
    *Note*: cannot be caught by server bc the `#` is not included in the request. It doesn't work without `unescape` bc the characters will be URL-encoded.
  - Variant 2 (`eval`):
    0. ```js <script>
  var data =  document.location.href.substring(document.location.href.lastIndexOf("data=") + 5);
  var compute = "13 * " + data;
  var result = eval(compute);
  document.write(result);
</script>```
    1. Click `ubuntu.test/attackdemo/general/DOMbased_XSS3.html?data=19#data=19;alert('XSS');`
    2. App reads last ocuurence of `data`: `data=19;alert('XSS');`
    3. Eval computes `13*19; alert("XSS");`
    *Note*: cannot be caught by server bc the `#` is not included in the request. `unescape` not used so `>`, `<` and `"` cannot be used (bc URL-encoded).
  - Var 4: SVG. Can contain `script` tags.
  - Var 5: Event handlers and alternative vectors ( `<img src="x" onerror />, <input onfocus="" autofocus />`)
  - *Counter*: avoid `unescape` and `eval`, avoid using JS to render elements controlled by user, 
  #inline("Broken Access Control")
  Access data or execute actions for which attacker isn't authorised
  #subinline("Function level")
  Access unauthorised function. E.g.: `/admin/post` EP does not check if user is actually admin
  #subinline("Object level")
  Attacker can use an authorised function in a manner that gives access to unauthorised objects (resources) \
  E.g.: non-randomised resource IDs (username, filename, PID...) \
  *Counter*: auth checks for every action and resource access, don't include resource IDs in URL or requests
  #inline("Cross-Site Request Forgery (CSRF)")
  Force another user to execute an unwanted action while they are authenticated
  - *GET*:
    0. Victim is logged into `shop.com`
    1. Victim clicks on bad `attacker.com` link, which display an image: `<img src="https://shop.com/transfer?amount=1000&to=attacker" width="1" height="1">`
    2. The image triggers a GET request to `shop.com`. Browser automatically attaches the `shop.com` cookie, so the request is valid.
  - *POST*:
    0. Victim is logged into `shop.com`
    1. Victim clicks on bad `attacker.com` link, which contains a 0x0 Iframe, which contains an auto-submitting form
  - *`fetch`*
    ```js
<script>
    fetch("shop.com", {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: "title=ATTACK&message=SUCCESS&SUBMIT=submit"
    });
</script>
    ```
    *Note:* works bc GET and POST are not subject to the Same Origin Policy
  - *Counter*: 
      - Use user session token stored in session storage. Pass it in REST bodies. Compare sent, received and stored tokens.
      - `Set-Cookie: SameSite`. `None` cookies are attached to all x-site requs, `Lax` cookies attached to GET x-site requs, `Strict` never attached. `lax` good but must ensure GET requs do not modify app state.
  #inline("Testing tools")
  - *ZAP*: Scans all requests then tries famous vulnes. But uses fixed vals that can block the app (e.g. incorrect form values)
  - *Fortify*: static code analyser. Doesnt see SQL injection or XSS.   
  - *Spotbug*: binary (JAR) analyser

  #inline("SSRF (server side request forgery)")
  Attacker makes it so the server requests data from itself instead of an external source, exposing its own data
  
  - *Attack*: Pass URL like `http://localhost:8080/admin` or `http://169.254.169.254/metadata` (cloud metadata)
  - *Localhost filter bypasses* (when app blocks "localhost" or "127.0.0.1"):
    - `0.0.0.0` = "all interfaces" on Linux, resolves to localhost
    - `[::1]` = IPv6 localhost (often forgotten in filters)
    - `2130706433` = decimal notation for 127.0.0.1
    - `0x7f000001` = hex notation for 127.0.0.1
    - `127.0.0.1.nip.io` = DNS rebinding, resolves to 127.0.0.1
  - *Fix*: Whitelist allowed domains, block ALL private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
])

= Buffer overflow & race cond (SDL 3 & 4)

#concept-block(body: [
  #subinline("Memory Layout")
  #grid(
    columns: (2fr, 10fr),
    gutter: 8pt,
    align: horizon,
    image("memory-layout.png"),
    [
      *Virtual address space*, low → high:
      - *Code*: Instruction pointers should point here
      - *Data*: Global and static variables
      - *Heap*: Dynamic memory (`malloc`/`new`). Grows ↑
      - *Stack*: Local vars, return addresses. Grows ↓
    ],
  )

  #subinline("Stack Mechanics")
  - *Stack frame*: Created per function call, destroyed on return
  - *Stack Pointer (rsp)*: "Where am I now?" → moves on every push/pop
  - *Base Pointer (rbp)*: "Where did my frame start?" → stays fixed, access local vars via offsets (`rbp-4`, `rbp-8`)
  - *old rbp*: Saved so caller's frame can be restored after return
  - *return address*: Where to jump back after function completes
  - Frame layout (low → high): `[local vars] [old rbp] [ret addr]`

  // #image("stack-frame.png")
#inline("Buffer overflows")
Modify the program flow, crash the program, inject (malicious) own code, access sensitive information...

#grid(
  columns: (auto, auto),
  image("buffo0.png"),
  [
    *`area` execution (leaf function)* \
    `rbp == rsp` bc we use *Red Zone* opti. Local vars stored using neg. offsets of `rbp` (no `subq` instr.)
  ],
  image("buffo1.png"),
  [
    *`main` return (non-leaf)*
    `rsp` points to top of stack to clearly delimitate `main`'s memory (no Red Zone opti)
  ]
)

#subinline("Exploit example")
```c
void processData(int socket) {
  char buffer[256], tempBuffer[12];
  int count = 0, position = 0;
  
  /* Read data from socket and copy it into buffer */
  count = recv(socket, tempBuffer, 12, 0);
  while (count > 0) {
    memcpy(buffer + position, tempBuffer, count)
    position += count;
    count = recv(socket, tempBuffer, 12, 0);
  }

  return 0;
}
```

#grid(
  columns: (28%, auto),
  image("buffoexploit.png"),
  [- Attacker sends more than `256 bytes` through socket. 
  - Bytes `265` to `272` overwrite `ret address`. Attacker can replace it with the beginning addr. of buffer. 
  - Bytes `0` to `264` contain attack code.
  - Attack code runs with same privileges as program.]
)

- *Counters:* Check boundaries for any input/output op, avoid `gets`, `strcpy`, static code ana & fuzzing, forbid exec of code in mem data segments,  Address Space Layout Randomisation (ASLR), 

#subinline("Stack canaries")
- Random 8 bytes val gen at start if program
- Pushed to stack right after `old rbp`
- Before returning to calling function, stack value is compared to saved generated value
- Program crashes/terminates if they don't match

#inline("Race conditions")
#subinline("TOCTOU (Time of Check Time of Write)")
```c
if(!access(file, W_OK)) {
  printf("Enter data to write to file: ");
  fgets(data, 100, stdin);
  fd = fopen(file, "w+");
  if (fd != NULL) {
    fprintf(fd, "%s", data);
  }
} else {  /* user has no write access */
  fprintf(stderr, "Permission denied when trying to open %s.\n", file);
}
```
Attacker can change the file `file` points to after the `if` check passed but before writing starts, e.g. using a symlink to a sensitive file he shouldn't access \
*Counters:* 
  - use as little functions that take filename as arg as possible. Use it for initial file access and return a reusable file descriptor (e.g. used to check write perm).
  - Let the OS handle perm checks and avoid running prog as root user.

```java 
public class SessionIDGenerator {
  private static Random rng = new Random();
  private static String newSessionID
  
  public static void createSessionID() {
    byte[] randomBytes = new byte[16];
    rng.nextBytes(randomBytes);
    newSessionID = Util.toHexString(randomBytes);
  }
  
  public static String getSessionID() {
    return newSessionID;
  }
}
```
1. Thread A calls `create`
2. Thread B calls `create`
3. Thread A calls `get`. But it will get User B's session ID.
])

= Fundamental Security Principles (SDL 1, 2, 3)
#concept-block(body: [
   Battle-tested, true back then, now and in the future. Tech-independent. 

   #inline("1. Secure the weakest link")
   Attackers target the weakest component. Fix high risk vulnes first. To identify:  threat modelling, penetration tests, and risk analysis
   #inline("2. Defense in depth")
   1. Defend multiple layers, not just the outter one (e.g. don't assume servers can communicate unencrypted bc you have setup a firewall and inner network is safe)
   2. Don't rely only on prevention. 
      1. Prevent (_long, safe pw requs_)
      2. Detect (_monitor large num of failed login_)
      3. Contain (_lock hacked accounts_)
      4. Recover (_ask users to reset pws, monitor attack IPs_)
  #inline("3. Fail securely")
  - *Version Downgrading Attack*: man in the middle convinces client and server that t.he other only supports old (vulnerable) protocol version. Server is configed to accept this.
  - *Fail open vulne*: `isAdmin` initialised to `true`. Function that sets it to the actual value throws an error. Error is caught and `if` check is executed. `isAdmin` is still `true` so sensitive code runs.
    ```java 
boolean isAdmin = true;
try {
  isAdmin = checkPermissions();
} catch (Exception ex) {
  log.write(ex.toString());
}
if(isAdmin) {
  // sensitive
}
```
  #inline("4. Principle of Least Privilege")
  Keep separate apps for users with separate needs (admin dashboard)
  #inline("5. Separation of Privileges")
  - Preventing that a single user can carry out and conceal an action (or an attack) completely on his own \
  - Separating the entity that approves an action, the entity that carries out an action, and the entity that monitors an action
  - E.g. _Different people are responsible for development vs testing+approval of deployment_
  #inline("6. Secure by Default")
  Default config must be secure. \
  Enforce 2FA, auto security updates, firewall on by default, minimal default permissions, no default pw (or force to change it) 
  #inline("7. Minimise attack surface")
  Include only necessary features, use packet-filtering firewalls to keep internal services hidden from Internet
  #inline("8. Keep it simple")
  Easier to maintain. Users shouldn't have to make important security decisions.
  -  Re-use proven software components 
  - Implement security-critical functions only once and place them in easily identifiable program components (e.g., in a separate security package)
  - Do not allow the users to turn off important security features
  #inline("Avoid Security by Obscurity")
  Security by Obscurity = system is secure bc attackers don't know how its internals work. \
  Good only as redundancy on top of other security measures. \
  Reverse eng: disassembler, decompilers.
  - *Source/Binary*: Transforms code into a functionally equivalent, unreadable version to protect IP during public delivery.
  - *Data*: Obscures storage/structures (e.g., splitting variables, changing encoding, promoting scalars to objects).
  - *Control Flow*: Reorders logic and injects false conditionals/junk code to break decompiler flow while preserving output.
  - *Preventive*: Targets RE tools by stripping metadata and renaming identifiers to gibberish (e.g., `calculate()` -> `x()`).
  #inline("Don't Trust User Input and Services")
  Always validate (+sanitate) the received data. Use defensive prog. \
  Prefer *whitelisting* over *blacklisting* (i.e. define what is allowed, not what is forbidden). Don't try fixing invalid data, just reject it.
])

= Java Security (SDL 4)

#concept-block(body: [
  #inline("General utils")
  #subinline("JCA (Java Cryptography Architecture)")
  Provider-based architecture: CSPs (Cryptographic Service Providers) implement algorithms. \
  Default providers included, 3rd party (e.g., Bouncy Castle) addable. Specify: `getInstance("SHA-256", "BC")`

  #subinline("Random Numbers")
  #text(fill: red)[`java.util.Random` is *NOT* secure] → use `SecureRandom`
  ```java
  SecureRandom random = new SecureRandom(); // uses OS entropy
  byte[] bytes = new byte[16];
  random.nextBytes(bytes);
  ```
  `setSeed()` *supplements* randomness (never reduces it). Default seeding usually sufficient.

  #subinline("Unkeyed hashing for integrity")
  *Goal*: ensure the data wasn't accidentally corrupted. #text(fill: red)[Does not prevent tampering].
  
  ```java
  MessageDigest md = MessageDigest.getInstance("SHA-256");
  md.update(data1); // feed data (can call multiple times)
  byte[] hash = md.digest(data2); // feed more data and compute hash
  ```
  *Secure:* SHA-256, SHA-512, SHA3-256, SHA3-512. #text(fill: red)[*Insecure:* MD5, SHA-1]

  #inline("Symmetric crypto (Shared secret key)")
  
  #subinline("Secret Key Gen")
  ```java
  KeyGenerator keyGen = KeyGenerator.getInstance("AES");
  keyGen.init(256); // key size: 128, 192, or 256
  SecretKey key = keyGen.generateKey();
  // From existing raw bytes:
  SecretKeySpec keySpec = new SecretKeySpec(rawBytes, "AES");
  ```
  #text(fill: red)[Password-based keys are *weak*] → use long random data or proper key derivation (PBKDF2).
  
  #subinline("Keyed HMAC (MAC hashing) to prevent tampering")
  *Goal*: prevent attacker from modifying the cipher and computing the hash.

  ```java
  Mac hmac = Mac.getInstance("HmacSHA256");
  SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
  hmac.init(secretKey);
  byte[] macResult = hmac.doFinal(data);
  ```

  #text(fill: red)[Always encrypt before calculating the MAC]
  
  #subinline("Symmetric Encryption (Cipher)")
  ```java Cipher.getInstance("algo/mode/padding") // AES/CBC/PKCS5Padding``` 
  - Algo: `AES` or `ChaCha20` (#text(fill: red)[Not `DES` or `3DES`])
  - Mode:
    - #text(fill: red)[*ECB*: Never use!] Encrypts block by block, leaking patterns
    - *CBC*: + MAC (Message Authentication Code) for integrity
      ```java cipher.init(mode, key, new IvParameterSpec(iv));```
    - *GCM*: Authenticated (confidentiality + integrity built-in)
      ```java cipher.init(mode, key, new GCMParameterSpec(128, iv)); //128 tag bits```
    - *CTR*: Stream mode

    
  For CBC/GCM/CTR, #text(fill: red)[never reuse the same *IV/Key* pair].
  Also, #text(fill: red)[Always re-init the cipher after `doFinal`]:
  ```java
for (byte[] msg : messages) {
  byte[] newIv = new byte[12]; // GCM standard IV length
  secureRandom.nextBytes(newIv); // Fresh randomness!
  
  cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, newIv));
  byte[] ciphertext = cipher.doFinal(msg);
  
  // Store newIv + ciphertext together so you can decrypt later
}
  ```

  #inline("Public Key crypto (Asymmetric)")
  #subinline("Key Pair Generation")
  
  ```java
  KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
  keyGen.initialize(2048); // Min 2048 bits for RSA
  KeyPair pair = keyGen.generateKeyPair();
  PublicKey pubKey = pair.getPublic();
  PrivateKey privKey = pair.getPrivate();
  ```
  
  #subinline("Asymmetric Encryption (RSA)")
  
  - Goal: Confidentiality for small data (e.g. keys).
  - `Cipher.getInstance("RSA/ECB/OAEPPadding")` (#text(fill: red)[Always use OAEP]). "ECB" is fine since RSA encrypts the entire message as one block.
  - #text(fill: red)[Size limit]: RSA 2048 can only encrypt up to 245 bytes.
  
  ```java
  cipher.init(Cipher.ENCRYPT_MODE, pubKey);
  byte[] ciphertext = cipher.doFinal(plaintext);
  ```
  
  #subinline("Hybrid Encryption (Key Wrapping)")
  
  - Goal: Encrypt large data by combining RSA (for key) with AES (for data).
  
  ```java
  // Sender: Wrap (encrypt) a random AES key with recipient's RSA public key
  cipher.init(Cipher.WRAP_MODE, recipientPubKey);
  byte[] wrappedKey = cipher.wrap(aesSessionKey);
  
  // Recipient: Unwrap (decrypt) AES key with own private key
  cipher.init(Cipher.UNWRAP_MODE, myPrivKey);
  Key aesKey = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
  ```
  
  #subinline("Digital Signatures")
  
  - Goal: Authenticity and Integrity. Sign with `PrivateKey`, verify with `PublicKey`.
  
  ```java
  Signature sig = Signature.getInstance("SHA256withRSA");
  sig.initSign(privKey);
  sig.update(data);
  byte[] signature = sig.sign();
  // Verification: sig.initVerify(pubKey) -> sig.update(data) -> sig.verify(signature)
  ```

  #inline("Storage and network")
  #subinline("JSSE (Java Secure Sockets Extension)")
  TLS sockets for secure communication. TLS 1.2/1.3 enabled by default (1.0/1.1 disabled, SSL not supported).
  ```java
  SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
  SSLSocket socket = (SSLSocket) sf.createSocket("host", 443);
  // Server: SSLServerSocketFactory → SSLServerSocket → accept()
  ```

  #subinline("Keystore vs Truststore")
  - *Keystore*: Own private key + certificate → used to authenticate *yourself* to others
  - *Truststore*: Trusted CA certificates (no private keys) → used to verify *peer's* certificate
  - *Server* needs keystore (prove identity to clients), *client* needs truststore (verify server)
  - *Mutual TLS*: Both sides need keystore AND truststore (`setNeedClientAuth(true)`)
  - Default truststore `$JAVA_HOME/lib/security/cacerts` contains official CA certs → public HTTPS works out of box
  
  #subinline("keytool (CLI for keystores)")
  - *Generate keypair:* `keytool -genkeypair -keyalg rsa -keysize 2048 -keystore ks.p12 -storetype PKCS12 -alias mykey`
  - *Export cert:* `keytool -exportcert -keystore ks.p12 -alias mykey -file cert.cer`
  - *Import cert to truststore:* `keytool -importcert -keystore ts.p12 -file cert.cer -alias peer`
  - *Run with stores:* `java -Djavax.net.ssl.keyStore=ks.p12 -Djavax.net.ssl.keyStorePassword=pw ...`

  #subinline("SSLContext (Programmatic Config)")
  Alternative to `-D` flags: configure TLS in code (for fine-grained control, mutual TLS, etc.). \
  Build from: *KeyManagerFactory* (own keys) + *TrustManagerFactory* (trusted certs)
  ```java
  KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
  kmf.init(keyStore, password);  // load own private key
  TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
  tmf.init(trustStore);          // load trusted certs
  SSLContext ctx = SSLContext.getInstance("TLSv1.3");
  ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
  ```
])

= Secure SSR webapps (SDL 3 & 4)

#concept-block(body: [
  Little client code, server returns full HTML pages. \
  *Warning:* in Spring Security, rules cascade in reverse CSS order: higher rule has priority
  #image("market.png")
  #inline("DB permissions")
  #image("dbperms.png")
  #inline("Spring config")
  `@EnableWebSecurity`: marks class as Spring Security config
  ```java
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
    .requiresChannel(channel -> channel.anyRequest().requiresSecure())
    .csrf(csrf-> csrf.disable());
    return http.build();
  }
  ```
  - `authorizeHttpRequest`: all requests are permitted without authentication (per default, Spring Security requires authentication for all requests)
  -  `requiresChannel`: all requests to HTTP are redirected to HTTPS
  -  `csrf`: disable Cross-Site Request Forgery protection
  #inline("Preventing Information leakage in Error Messages")
  1. Add Spring templates for each type of errors (`500.html`, ...) to show a generic message
  2. Remove the following from `application.properties`:
     ```toml 
     server.error.whitelabel.enabled=false
     server.error.include-exception=true
     server.error.include-message=always
     server.error.include-stacktrace=always
     ```
  3. Catch errors and `return 0` inside `catch` blocks
  #inline("Data Sanitation")
  #image("brianisinthekitchen.png")
  Risk of Reflected XSS vulne (`<script>alert("XSS")</script>`) \
  2 fixes:
  1. Input validation: Do not accept search strings that include JavaScript code
  2. Data sanitation: Encode critical control characters before the search string is included in the webpage (e.g., replace `<` with `&lt;`) (`th:text` in Thymeleaf) \
     *Required* because:
     1. Users might want to search for JS code
     2. Input validation might be turned off for new user needs in the future
  *Important*: perform sanitation for all content that comes from external components (i.e. not the server code): client, database, file...
  #inline("Secure Database Access (SQL inj)")
  Use prepared statements
  ```java
  String sql = "SELECT * FROM Product WHERE Description LIKE ?";
  return jdbcTemplate.query(sql, new ProductRowMapper(), "%" + description + "%");
  ```

  ```java
  String sql = "INSERT INTO Purchase (Firstname, Lastname, CreditCardNumber, TotalPrice) "
  + "VALUES (?, ?, ?, ?)";
  return jdbcTemplate.update(sql, purchase.getFirstname(), purchase.getLastname(),
  purchase.getCreditcardnumber(), purchase.getTotalprice());
  ```
  #subinline("Bad JPA examples")
  Good: Always extend `CrudRepository`.   
  Note: JPQL does not support UNION \
  
   Used JPA directly via class `EntityManager`and used JPQL query using string concatenation. ```sql no-match%' OR '%' = '```
  ```java
  public class ProductVulnerableRepository {
    @Persis§§ tenceContext
    private EntityManager entityManager;
    public List<Product> findByDescriptionContaining(String description) {
      Query query = entityManager.createQuery("SELECT p FROM Product p 
      WHERE p.description LIKE '%" + description + "%'");
      return query.getResultList(); 
    }
  ```
  `EntityManager` is used, together with a native query and string concatenation
  ```java
  public List<Product> findByDescriptionContaining(String description) {
    Query query = entityManager.createNativeQuery("SELECT * FROM Product
    WHERE Description LIKE '%" + description + "%'");
    List<Object[]> results = query.getResultList();
    List<Product> products = new ArrayList<>();
    Product product;
    for (Object[] result : results) { // copy from results to products }
    return products;
  }
  ```
  #inline("Authentication and Access Control")
  #subinline("Secure Storage of Passwords")
  No plaintext or level-1 hashes. Use complex hashing (bcrypt, Argon2...) or 5000+ rounds of fast hashing (SHA-512, `Hash = SHA-512(SHA-512(...|salt|password))`).
  *bcrypt*: `$<version>$<cost>$<salt><hash>` (cost = rounds, salt&hash char counts)
  #subinline("Authentication Mechanism")
  - *HTTP basic auth*: shows a login dialog when server returns a 401, send the username+pw as a (base64-encoded) HTTP Authorisation Header in *every* future REST call. *Can only be cleared by closing the browser.* There is no logout feature.
    ```java http
.authorizeHttpRequests(...)
.httpBasic(withDefaults()) ```
  - *Form auth*:
    *Always use POST not GET* (GET includes the form data as URL params)
    ```java
    http
    .authorizeHttpRequests( ... )
    .formLogin(formLoginConfigurer-> formLoginConfigurer
    .loginPage("/public/login")
    .failureUrl("/public/login?error=true")
    .permitAll())
    ```
    #subinline("CSRF protection (Cross-Site Request Forgery)")
    Set `SameSite` to _Lax_ in `application.properties`

    #subinline("Sessions")
    `Set-Cookie: session-id=28A46...; expires=Fri, 23-Dec-2035 11:09:37 GMT; Domain=www.example.com; Path=/myexample; Secure; HttpOnly; SameSite=Lax`
    - `session-id=...`: The name & value of the cookie session ID. Must be long and random.
    - `expires`: if no expiry date is used, the cookie is deleted when closing the browser (*good for session cookies*)
    - `Domain`, `Path`: Any request to resources below `www.example.com/myexample/` includes the cookie
    - `Secure`: Only send the cookie over HTTPS
    - `HttpOnly`: JavaScript cannot access the cookie via `document.cookie`
    - `SameSite`: Specifies when cookies should be included in cross-site requests (_Lax_: only GET requests)

    In `application.properties`:
    ```toml
    server.servlet.session.cookie.http-only=true
    server.servlet.session.cookie.secure=true
    server.servlet.session.timeout=10m
    ```

    #subinline("Input validation")
    ```java 
    @GetMapping("/public/products")
    public String productsPage(@ModelAttribute @Valid ProductSearch productSearch, BindingResult bindingResult, Model model) {
      if (bindingResult.hasErrors()) {
        model.addAttribute("products", new ArrayList<Product>());
        productSearch.setDescription("");
        model.addAttribute("productSearch", productSearch);
      } 


    public class ProductSearch {
      @Size(max = 50, message = "No more than 50")
      private String description = "";
    ```

    `@Valid` tells Spring to enforce the `@Size` constraint. It stores the result in `BindingResult`. If there is an error, we show an empty product list.
])

= Secure CSR webapps (SDL 3 & 4)

#concept-block(body: [
  #inline("JSON Web Tokens")
  #subinline("Structure")
  Header 
  ```json
  {
    "alg":"HS256" // which MAC algo to use
  }
  ```
  Payload 
  ```json
  {
    "iss":"Marketplace", // issuer
    "sub":"alice", // subject
    "exp":"1749281266" // expiry date
  }
  ```
  MAC (Message Authentication Code)
  ```
  HMAC-SHA256(header + "." + payload, key) // key known only by REST service server/backend
  ```
  Final full token
  #text(fill: red, "Base64(header)")\.#text(fill: green, "Base64(payload)")\.#text(fill: blue, "Base64(MAC)")
  #subinline("Props")
  - cannot be forged due to secret HMAC key
  - expires
  - verifying the HMAC is fast
  - stateless (self-contained)
  - URL safe (no char encoding)
  #subinline("How")
  1. User authenticates using username+pw
  2. Backend checks the pair in DB. If correct, it generates a JWT and sends it back
  3. Client includes the JWT in every request
  4. Backend extracts the username from the token
  #inline("Erros")
  - `CustomAccessDeniedHandler`: access control error (insufficient perm)
  -  `InvalidParameterException`: Auth failed or invalid ID passed
  - `MethodArgumentNotValidException`: `@Valid` is used and validation fails
  - `ConstraintViolationException`: Bean Validation annotations are used with method parameters (e.g., @`Min` and `@Max`) and validation fails
  - `MethodArgumentTypeMismatchException`: Thrown if a path parameter has the wrong type (e.g., a purchase ID of type int is expected, but a string is received)
  - `RuntimeException`: Thrown if storing a purchase in the database does not work
  #inline("Config")
  ```java
  // filter every request with the auth checker
  http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
  .exceptionHandling(exception -> exception
  .accessDeniedHandler(accessDeniedHandler)
  .authenticationEntryPoint(authenticationEntryPoint))
  .cors(Customizer.withDefaults());
  ```
  #inline("CORS")
  ```java
  CorsConfiguration config = new CorsConfiguration();
  config.setAllowedOrigins(Arrays.asList("*"));
  config.setAllowedMethods(Arrays.asList("OPTIONS", "GET", "POST", "DELETE"));
  config.setAllowedHeaders(Arrays.asList("*"));
  UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
  source.registerCorsConfiguration("/rest/**", config);
  return source
  ```
  - *Origin*: Protocol (`https://`), domain (`example.com`), port (`:8181`)
  - Default `fetch` behaviour: only GET and POST cross-origin requests are allowed. Cannot contain auth. header (JWT), can't use ` application/json` content type, can't view the server's response
  - Use CORS config to whitelist request origins and methods. *Preflight* requests use method `OPTIONS`, `Access-Control-Request-Method` and `Access-Control-Request-Headers: authorization`
  - What if we need to allow requests form `*`?
    - If no auth, no need because attacker can use same requests as all users
    - If auth, we must 
      - avoid cookies: since they can be included in the request `fetch("https://url", {credentials: "include",...});`
      - use Bearer Tokens (e.g. JWT) *stored in session (or local) storage*. Attacker cannot access it because the origin of the malicious page is different from the real one storing the token. But this brings back risk of XSS attacks

  #subinline("Preflight")
  Browser sends `OPTIONS` first to ask if request is allowed:
  ```http
  OPTIONS /rest/admin/purchases/3
  Access-Control-Request-Method: DELETE
  Access-Control-Request-Headers: authorization
  ```
  Server responds with what's allowed:
  ```http
  Access-Control-Allow-Origin: https://localhost:8081
  Access-Control-Allow-Methods: OPTIONS, GET, POST, DELETE
  Access-Control-Allow-Headers: authorization
  ```
      
    #inline("Storage")
    - `local`: shared across tabs of same origin, persists browser closure
    - `session`: scoped to the tab or browser window and cleared on browser closure
])

= Security Requirements Engineering and Threat Modeling

#concept-block(body: [
  #inline("Security Requirements Engineering")
  - If not done: security flaws missed, can't do focused pen tests to verify requs are implemented
  - Based secu requs on app's functional requs is not enough
  - Describes the what must be protected, not the how (tech impl)

  // #table(
  //   columns: (0.8fr, 2fr, 1.5fr),
  //   "Identify the business and security goals (interviews)", [], [
  //     - The system allows its users efficient access to online functions of the university library
  //     - The integrity of the system and its data shall be maintained
  //     - The confidentiality of personal user data and credentials shall be guaranteed
  //     - Any system activity is logged and can be linked to the user that carried out the activity
  //   ],
  //   "Collect info (interviews, artefacts)", [
  //     - What features offered?
  //     - Who are users?
  //     - What data is processed?
  //     - What are the most important assets?
  //     - How does the system work (components, technologies, interactions,...)?
  //     - What are the external dependencies?
  //     - What is the minimum availability (24/7)?
  //     - Existing secu requs
  //   ], [
  //     - 3 users: students, staff, librarians
  //     - Students and staff can log in, search and reserve books, download e-books
  //     - Librarians can manage reservations and users. They all share one account.
  //     - *Availability* not important, down times ok
  //     - *Ext. deps*: Linux, Java Spring Boot, MySQL, server firewall
  //     - *Existing requs*: HTTPS TCP 443
  //     - *Assets*: server-side systems, user data, user creds, logs
  //   ],
  //   "Decompose the system", [
  //     - Network diagram
  //     - Just enough detail to identify threats
  //     - Include all assets
  //   ], [
  //     #image("uniapp.png")
  //   ]
  // )
  #subinline("1. Identify the business and security goals (interviews)")

  - The system allows its users efficient access to online functions of the university library
  - The integrity of the system and its data shall be maintained
  - The confidentiality of personal user data and credentials shall be guaranteed
  - Any system activity is logged and can be linked to the user that carried out the activity
  
  #subinline("2. Collect info (interviews, artefacts)")
  
  *Questions:*
  - What features offered?
  - Who are users?
  - What data is processed?
  - What are the most important assets?
  - How does the system work (components, technologies, interactions,...)?
  - What are the external dependencies?
  - What is the minimum availability (24/7)?
  - Existing secu requs
  
  *Details:*
  - 3 users: students, staff, librarians
  - Students and staff can log in, search and reserve books, download e-books
  - Librarians can manage reservations and users. They all share one account.
  - *Availability* not important, down times ok
  - *Ext. deps*: Linux, Java Spring Boot, MySQL, server firewall
  - *Existing requs*: HTTPS TCP 443
  - *Assets*: server-side systems, user data, user creds, logs
  
  #subinline("3. Decompose the system")
  
  - Network diagram
  - Just enough detail to identify threats
  - Include all assets
  
  #image("uniapp.png")

  *Data flow:* 
  #grid(
    columns: (auto, auto, auto),
    figure(image("proc.png"), caption: [A task that transforms an input into an output]),
    figure(image("proc2.png"), caption: [Multiple procs]),
    figure(image("users.png"), caption: [External entity]),
    figure(image("datastore.png"), caption: [Data store (DB, config files, logs...)]),
    figure(image("trust.png"), caption: [Trust Boundary:  separate components that should not automatically trust each other]),
  )

  #image("unidf.png")

  Login:
  #image("loginuni.png")

  #subinline("4. Identify Threats, Risks, and Vulnerabilities")
  - #strong[S]poofing: Attackers usurps identity
  - #text(weight: "bold", "T")ampering: Modifying data or code without authorisation (rest or in transit) 
  - #text(weight: "bold", "R")epudiation: No way to tie an action to a user, the attacker can deny having performed the attack
  - #text(weight: "bold", "I")nformation Disclosure: Exposing data to unauthorised users (SQL inj)
  - #text(weight: "bold", "D")enial of Service: Impacting the availability of a system or service
  - #text(weight: "bold", "E")levation of Privilege: Gaining higher levels of access than intended (prog running in root)

  #image("stride.png")

  #inline("Threat Agents")
  - *Script Kiddies*: Fun/fame, low skill. Free tools, low-hanging fruit
  - *Insiders*: Revenge/profit, low-med skill. Abuse legitimate access, know protections
  - *Hacktivists*: Embarrass orgs, low-med skill. DDoS, defacement
  - *Cyber Criminals*: Profit, med-high skill. Phishing, ransomware, botnets
  - *Nation States*: Intelligence, unlimited resources. Specific targets, will do anything
  Key: Criminals pick easy targets, nation states persist until success
  #image("elisa.png")

  #colbreak()
  
  - Apply STRIDE to DF diag:

  #grid(
    row-gutter: 8pt,
    columns: (auto, auto, auto),
    figure(image("idk.png"), caption: [Librarian pw is shared and has no minimal requs -> *spoofing* threat]),
    figure(image("repulib.png"), caption: [Since librs share one account, there is a *repudiation* risk]),
    figure(image("studentss.png"), caption: [Students can snip the creds (*info disclosure*) or *tamper* but we use HTTPS #underline[so no vulne]]),
    figure(image("spoofspoof.png"), caption: [*Spoofing* threat if attacker creates own copy of web app, but real app has certif from trusted authority #underline[so no vulne]]),
    figure(image("spoofspoof.png"), caption: [*Tampering* if attacker modifies web app code or Tomcat config, but we use Java and hardened uni server, #underline[so no vulne]]),
    figure(image("tamperr.png"), caption: [Webapp may contain vulne allowing write access to the files -> *tampering*]),
  )

    Data Store vs. Process Tampering: modify program code on server vs modify web app code while running, different ways to tamper so diff vulnes

    #image("strideuni.png")
])

= Security Risk Analysis (Horizontal Activity)

#concept-block(body: [
  #image("riskan.png")
  
  #inline("Purpose")
  - Rate *risk* (criticality) of vulnerabilities, threats, bugs → decide whether to address or not
  - Complements: threat modeling, code review, pen testing, operations

  #inline("The 4-Step Process")
  1. *Identify vulnerabilities*: Via threat modeling, pen testing, code review
    - Document: attack, threat agent, vulnerabilities, existing controls
  2. *Estimate likelihood & impact*: For each vulnerability
  3. *Determine risk*: Based on likelihood x impact
  4. *Risk mitigation*: Decide actions, implement corrective measures

  #inline("Quantitative vs Qualitative")
  - *Quantitative*: $"ALE" = "SLE" times "ARO"$ (annual financial loss)
    - $"SLE"$ = Single Loss Expectancy (cost per incident)
    - $"ARO"$ = Annualised Rate of Occurrence (incidents/year)
    - Example: DB breach every $5 "year"$, costs $100K$ → $"ALE" = 100K times 0.2 = 20K\/"year"$
    - Hard to estimate for IT risks (unknown attacker behaviour)
  - *Qualitative*: Likelihood & impact as levels (Low/Med/High) → preferred in practice

  #inline("NIST 800-30 (simpler)")
  *Simpler* -> more accurate, better for beginners or new threats \
  *Controls*: safeguards or countermeasures
  
  Simple methodology, 3 levels each for likelihood & impact:
  - *Likelihood*:
    - High: Threat agent motivated & capable, controls ineffective
    - Medium: Motivated & capable, but controls provide some protection
    - Low: Lacks motivation/capability, or controls prevent
  - *Impact*:
    - High: Highly costly loss, significant harm to mission/reputation, death/serious injury
    - Medium: Costly loss, harm to mission/reputation, injury
    - Low: Some loss, noticeably affects mission/reputation


#colbreak()

  #inline("OWASP Risk Rating (detailed/structured)")
  More structured: rate factors 0-9, average them. If factor irrelevant → skip (-)
  
#subinline("1. Likelihood Factors")
#text(size: 4.6pt)[
#table(
  columns: (3fr, 5fr, 1fr),
  align: (left, left, center),
  [*Factor*], [*Criteria / Values*], [*Score*],
  [Threat Actor Skill (skill of whoever happens to attack us, NOT skill needed to succesfully exploit)], [
    - None (1)
    - Some (3)
    - Advanced (5)
    - Network/Programming (6)
    - Security Professional (9)
  ], [],
  [Threat Actor Motive], [
    - Low Reward (1)
    - Possible (4)
    - High Reward (9)
  ], [],
  [Access Opportunity], [
    - Full access needed (0)
    - Special (4)
    - Some (7)
    - None needed (9)
  ], [],
  [Population Size], [
    - Developers (2)
    - System Admins (2)
    - Intranet (4)
    - Partners (5)
    - Authenticated (6)
    - Anonymous (9)
  ], [],
  [Ease of Discovery (see if target is affected by vulne)], [
    - Impossible (1)
    - Difficult (3)
    - Easy (7)
    - Automated (9)
  ], [],
  [Ease of Exploit], [
    - Theoretical (1)
    - Difficult (3)
    - Easy (7)
    - Automated (9)
  ], [],
  [Awareness Level (is vulne already known)], [
    - No one knows about it (1)
    - Hidden (4)
    - Obvious (6)
    - Public (9)
  ], [],
  [Intrusion Detection], [
    - Active (1)
    - Logged and Reviewed (3)
    - Logged only (8)
    - None (9)
  ], [],
  table.cell(colspan: 2, align: right)[*Sum (of above 8):*], [],
  table.cell(colspan: 2, align: right)[*Likelihood Average (Sum / 8):*], []
)
]

#subinline("2. Impact Factors")
#text(size: 4.6pt)[
#table(
  columns: (3fr, 5fr, 1fr),
  align: (left, left, center),
  [*Factor*], [*Criteria / Values*], [*Score*],
  [Financial Damage], [
    - Less than cost to Fix (1)
    - Minor (3)
    - Significant (7)
    - Bankruptcy (9)
  ], [],
  [Reputation Damage], [
    - Minimal (1)
    - Accounts Lost (4)
    - Goodwill (5)
    - Brand Damage (9)
  ], [],
  [Non-Compliance], [
    - Minor (2)
    - Clear Violation (5)
    - High Profile (7)
  ], [],
  [Privacy Violation], [
    - Single individual (3)
    - Hundreds (5)
    - Thousands (7)
    - Millions (9)
  ], [],
  table.cell(colspan: 2, align: right)[*Sum (of above 4):*], [],
  table.cell(colspan: 2, align: right)[*Impact Average (Sum / 4):*], []
)
]

#colbreak()

  #subinline("3. Risk Mapping")
  #table(
    columns: (1fr, 1fr, 1fr),
    align: center,
    [*0-3*], [*3-6*], [*6-9*],
    [Low], [Medium], [High]
  )

  #inline("Risk Matrix (both methods)")
  #table(
    columns: (auto, auto, auto, auto),
    stroke: 0.3pt,
    inset: 2pt,
    [], [*Impact Low*], [*Impact Med*], [*Impact High*],
    [*Likelihood High*], table.cell(fill: rgb("ffe066"))[Medium], table.cell(fill: rgb("ffa94d"))[High], table.cell(fill: rgb("ff6b6b"))[Critical],
    [*Likelihood Med*], table.cell(fill: rgb("8ce99a"))[Low], table.cell(fill: rgb("ffe066"))[Medium], table.cell(fill: rgb("ffa94d"))[High],
    [*Likelihood Low*], table.cell(fill: rgb("dee2e6"))[Info], table.cell(fill: rgb("8ce99a"))[Low], table.cell(fill: rgb("ffe066"))[Medium],
  )
  - *Critical*: Stop operations, fix immediately
  - *High*: Fix ASAP (days to weeks)
  - *Medium*: Fix within reasonable time (next release)
  - *Low/Info*: Accept or fix if easy

  #inline("Risk Mitigation Options")
  - *Accept*: Risk too small, corrective action not worth it
  - *Reduce*: Implement measures to lower likelihood or impact
  - *Avoid*: Remove the functionality entirely
  - *Transfer*: Insurance, outsource
  - *Ignore*: Know the risk but do nothing (bad practice)

  #inline("Key Points")
  - Combine methods: NIST 800-30 for most, OWASP for uncertain cases
  - Risk analysis is subjective → do in team for better results
  - Don't over-precise with OWASP (4 vs 5 doesn't matter much)
  - Be pessimistic when unsure
  - Cost-effective solutions: don't spend more than expected damage
  - *Black Swans*: Low likelihood + High impact = Medium, but can be devastating → may have to accept and live with such risks
])

= Quick Reference

#concept-block(body: [
  #inline("Regular Expressions (Regex)")

  #subinline("Security Rule: Always Anchor")
  - `^pattern$` = matches *entire* string (secure) → use this for validation
  - `pattern` = matches *substring* (insecure) → `evil../../etc/passwd` passes `[a-z]+`

  #subinline("Syntax")
  - *Quantifiers*: `?` zero/one | `+` one or more | `*` zero or more | `{n,m}` n to m times
  - *Character classes*: `[abc]` match a, b, or c | `[^abc]` NOT a, b, c | `[a-z]` range
  - *Shortcuts*: `.` any | `\s` whitespace, `\S` NOT | `\w` word, `\W` NOT | `\d` digit, `\D` NOT
  - *Word boundary*: `\b` marks edge between word/non-word (`\bcat\b` matches "cat" not "category")
  - *Anchors*: `^` start of string | `$` end of string
  - *Grouping*: `(ab)+` matches "abab" (apply quantifier to group) | `cat|dog` matches "cat" or "dog"
  - *Escape*: `\.` for literal dot (special chars: `. * + ? ^ $ { } [ ] ( ) | \`)

  #subinline("Common Validation Patterns")
  - *Alphanumeric*: `^[a-zA-Z0-9]+$`
  - *Filename (safe)*: `^[a-zA-Z0-9_.-]{1,100}$` (no slashes)
  - *Username*: `^[a-zA-Z][a-zA-Z0-9_]{2,31}$` (letter first, 3-32 chars)
  - *Blacklist dangerous*: `^[^<>\"';&|$(){}\\[\\]]+$`

  #inline("URL Encoding Reference")
  *Path traversal*: `/` → `%2F` | `.` → `%2E` | `\` → `%5C` \
  *XSS/HTML*: `<` → `%3C` | `>` → `%3E` | `"` → `%22` | `'` → `%27` \
  *Other*: ` ` → `%20` | `%` → `%25` | `&` → `%26` | `#` → `%23` \
  *Rule*: Decode BEFORE validation, never after!

  #inline("Shell Metacharacters")
  - *Separators*: `;` (chain) | `|` (pipe) | `&` (background) | `&&`/`||` (conditional)
  - *Substitution*: ``` ` ` ``` or `$()` executes command, inserts output
  - *Redirection*: `>` `<` `>>` (write/read/append files)
  - *Quoting*: `"` `'` (escape context) | `\` (escape char)
  - *Variables*: `$VAR` or `${VAR}` expands variable value

  #inline("Linux File Permissions (ls -l)")
  ```
  -rwxr-xr-x  1  root  root  8312  Jan 8 2021  java
  │└┬┘└┬┘└┬┘  │   │     │     │       │         └─ filename
  │ │  │  │   │   │     │     │       └─ modified
  │ │  │  │   │   │     │     └─ size (bytes)
  │ │  │  │   │   │     └─ group owner
  │ │  │  │   │   └─ user owner
  │ │  │  │   └─ hard links
  │ │  │  └─ other: r-x = 4+1 = 5
  │ │  └─ group: r-x = 4+1 = 5
  │ └─ owner: rwx = 4+2+1 = 7
  └─ type: - file | d dir | l symlink
  ```
  - *Bits*: `r` read (4) | `w` write (2) | `x` execute (1) | `-` none (0) → sum per group

  #inline("HTTP Status Codes")
  - *2xx Success*: `200` OK | `201` Created | `204` No Content
  - *3xx Redirect*: `301`/`302` Redirect (check for open redirect vulnerability)
  - *4xx Client Error*: `400` Bad Request | `401` Unauthorized (no/invalid auth) | `403` Forbidden (valid auth, no permission) | `404` Not Found
  - *5xx Server Error*: `500` Internal Error (check for info leak) | `502` Bad Gateway | `503` Service Unavailable

  #inline("Common Ports")
  - *Web*: 80 (HTTP) | 443 (HTTPS) | 8080/8443 (alt)
  - *Auth/Mail*: 22 (SSH) | 21 (FTP) | 25 (SMTP) | 389 (LDAP)
  - *Databases*: 3306 (MySQL) | 5432 (PostgreSQL) | 1433 (MSSQL) | 27017 (MongoDB) | 6379 (Redis)

  #inline("Crypto Algorithms (JCA)")
  *Symmetric*: AES (128/192/256-bit key, 16B IV) | CHACHA20 (256-bit key, 12B nonce) | SEED (128-bit, Bouncy Castle) \
  *Modes*: CBC (+ separate MAC) | GCM (authenticated) | CTR (stream) | ECB (never use!) \
  *Hashing*: SHA-256, SHA-512, SHA3-256, SHA3-512 (secure) | MD5, SHA-1 (insecure) \
  *MAC*: `HmacSHA256`, `HmacSHA512`, `HmacSHA3-256`, `HmacSHA3-512` \
  *Signatures*: `SHA256withRSA`, `SHA512withRSA`, `SHA3-256withRSA`

  #inline("Recon & Exploitation Tools")
  - *Directory discovery*: `gobuster dir -u https://target -w /usr/share/wordlists/dirb/common.txt`
    - Add `-d` flag to detect backup files (`file~`, `.file.swp`)
  - *SQLMap*: `sqlmap -r request.txt --force-ssl --dbs` (auto SQLi, `--technique=B` for blind only)
  - *John the Ripper*: `john --format=raw-sha256 --wordlist=wordlist.txt hashes.txt` (format: `user:hash`)
  - *JWT decode*: `echo 'eyJhbG...' | cut -d'.' -f2 | base64 -d` or use jwt.io
  - *Burp Suite*: Intercept/modify requests, Intruder for fuzzing, Sequencer for session analysis
  - *ZAP*: Alternative to Burp, Fuzzer not rate-limited
  - *Request Catcher*: Receive exfiltrated data (requestcatcher.com) - use `/debug` endpoint to view requests
  - *curl with auth*: `curl -u "user:pass" https://target` | with proxy: `curl -x http://127.0.0.1:8080`
  - *Check IP via Tor*: `proxychains -q curl -s ifconfig.io`

  #inline("Information Disclosure Patterns")
  #subinline("Backup Files")
  Editors leave recoverable backups. Try these patterns on discovered files:
  - `file~` (vim backup) | `file.bak` | `.file.swp` (vim swap) | `#file#` (emacs)
  - `file.old` | `file.orig` | `file.save` | `file.php~`

  #subinline("Hash Identification")
  - 32 hex = MD5: `5d41402abc4b2a76b9719d911017c592`
  - 40 hex = SHA-1: `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`
  - 64 hex = SHA-256: `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c...`
  - `$2a$`, `$2b$`, `$2y$` prefix = bcrypt | `$argon2` prefix = Argon2
])

// TODEL -- course outline
#image("Screenshot 2025-12-06 185927.png")