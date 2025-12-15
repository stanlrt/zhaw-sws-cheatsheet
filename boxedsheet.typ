#import "@preview/boxed-sheet:0.1.1": *

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

#let subinline(title) = context {
  let heading-count = counter(heading).at(here()).first()
  let current-color = color-box.at(calc.rem(heading-count - 1, color-box.len()))

  box(grid(
    columns: (1fr, auto, 1fr),
    align: horizon + center,
    column-gutter: 1em,
    line(length: 100%, stroke: (paint: current-color, thickness: 1pt, dash: "dashed")),
    text(fill: current-color, weight: "regular")[#title],
    line(length: 100%, stroke: (paint: current-color, thickness: 1pt, dash: "dashed")),
    )
  )
}

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
  #inline("Security activities")
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

= Web app testing (SDL 5 & 6)
#concept-block(body: [
  Many web apps, security low and critical data (banking, e-commerce...)
  OWASP: Top Ten, Testing Guide, App Secu Verif Standard, WebGoat (bad app example)
  #image("webappsbasic.png")
  #inline("Injection attacks")
  #subinline("SQL")
  - Tools: ```sql OR ``==`` ```, ```sql UNION interesting_cols FROM interesting_table```, ```sql ; UPDATE employee SET password = 'foo'-```
  - If multiple params: use ```sql --``` to make rest of query a comment
  - Use ```sql ;``` to execute separate queries, only if server uses `executeBatch()`
  - Insert user: ```sql userpass'), ('admin', 'Superuser', 'adminpass')--```
  - *Testing*:
    - Set password to single-quote ' and see if DB returns error
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
  - *Countermeasures:* Prepared statements (```java $sth = prepare("SELECT id FROM users WHERE name=? AND pass=?"); execute($sth, $name, $pass);``` yields ```sql SELECT id FROM users WHERE name='\' OR \'\'=\'' AND pass='\' OR \'\'=\'';```)
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
  
])

// TODEL
#image("Screenshot 2025-12-06 185927.png")