#import "lib.typ": *

#set text(font: "Roboto")
#set text(lang: "en", //TODO LANG DE/EN
    region: "gb")


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
  - New targets: custom web apps, ransomware
  #inline("Defect types")
  - *Bug*: Problem introduced during *implementation* (e.g. error in a function that checks the passwords entered by users). _Can often be discovered by manual or automatic code inspection._
  - *Design flaw*: Problem introduced during the *design* (e.g. poorly designed password reset mechanism). Spotting them there is much more difficult, as a deeper understanding is required. _Can be uncovered by performing threat modelling_
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
  4. *Time & state*: issues due to parallelisation of tasks across multiple system. _eg: deadlocks, file access race condition (attacker changed file pointer after access was checked but before it is written to), reuse of session IDs_
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
  - Tools: ```sql OR ``==`` ```, ```sql UNION interesting_cols FROM interesting_table```, ```sql ; UPDATE employee SET password = 'foo'-```
  - If multiple params: use ```sql -- ``` to make rest of query a comment. In MySQL the space at the end is required.
  - Use ```sql ;``` to execute separate queries, only if server uses `executeBatch()`
  - Insert user: ```sql userpass'), ('admin', 'Superuser', 'adminpass')--```
  - *Testing*:
    - Set password to single-quote ' and see if DB returns error. Inject `SLEEP`
    - *Getting table names*: ```sql SELECT * FROM user_data WHERE last_name = Smith' UNION SELECT 1,TABLE_NAME,3,4,5,6,7 FROM INFORMATION_SCHEMA.SYSTEM_TABLES--``` 
      1. We assume `user_data` has 7 columns, all `int` except the 2nd one which is `string`
      2. We set the `UNION` query so that all columns but the 2nd are string literals (arbitrary numbers)
      3. We set the 2nd column to `TABLE_NAME` and query the `INFORMATION_SCHEMA.SYSTEM_COLUMNS`
      4. Second column contains one table name per row
    - *Getting column names of a table*: ```sql SELECT * FROM user_data WHERE last_name = Smith' UNION SELECT 1,COLUMN_NAME,3,4,5,6,7 FROM INFORMATION_SCHEMA.SYSTEM_COLUMNS WHERE TABLE_NAME = 'EMPLOYEE'--```
      3. We set the 2nd column to `COLUMN_NAME` and query the `INFORMATION_SCHEMA.SYSTEM_COLUMNS` for table `EMPLOYEES`
      4. Second column contains one column name per row
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
  - Java `Runtime.exec()` instead of `FileReader`/`FileInputStream`, PHP `system()`
  - *Test*: Analyse REST request, e.g. `HelpFile` field. Append `"` after filename and check for err. Append `; ipconfig`/` & ipconfig` (nix/msft). Might need to prepend `"` if app uses file path.
  - *Counter*: 
    - use IO classes instead of OS runtime
    - use character whitelisting (ban quotes...)
    - run process with minimal privieges
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
- *Counter:* blacklist < and >, disabled ext. entities in XML parser

#inline("Auth & session")
#subinline("Broken auth")
- Attacker gets credentials (weak pw, reset pw)
- Prerequ: unlimited login attempts allowed
- *Brute-force*: try common usernames and pws, email enumeration (time or msg), create account and see if email taken. *Remove cookie headers for new session* \
  *Counter:* vague msg ("Login failed"), CAPTCHA to rate limit accnt creation
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
])

= Buffer overflow & race cond (SDL 3 & 4)

#concept-block(body: [
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
  Always validate the received data. Use defensive prog. \
  Prefer *whitelisting* over *blacklisting* (i.e. define what is allowed, not what is forbidden). Don't try fixing invalid data, just reject it.
])

= Secure SSR webapps (SDL 3 & 4)

#concept-block(body: [
  Little client code, server returns full HTML pages.
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
  
])

= Secure CSR webapps (SDL 3 & 4)

// TODEL -- course outline
#image("Screenshot 2025-12-06 185927.png")