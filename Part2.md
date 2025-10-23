## Part 2

#### 1. Explain the need for security in databases 

Organizational databases tend to concentrate sensitive information in a single logical system. Examples include:
- Corporate financial data
- Confidential phone records
- Customer and employee information, such as name, Social Security number, bank account information, and credit card information
- Proprietary product information
- Health care information and medical records

For many businesses and other organizations, it is important to be able to provide customers, partners, and employees with access to this information. But such information can be targeted by internal and external threats of misuse or unauthorized change. Accordingly, security specifically tailored to databases is an increasingly important component of an overall organizational security strategy.

[BENN06] cites the following reasons why database security has not kept pace with the increased reliance on databases:

1. There is a dramatic imbalance between the complexity of modern **database management systems (DBMS)** and the security techniques used to protect these critical systems. A DBMS is a very complex, large piece of software, providing many options, all of which need to be well understood and then secured to avoid data breaches. Although security techniques have advanced, the increasing complexity of the DBMS—with many new features and services—has brought a number of new vulnerabilities and the potential for misuse.

2. Databases have a sophisticated interaction protocol called the **Structured Query Language (SQL)**, which is far more complex, than for example, the Hypertext Transfer Protocol (HTTP) used to interact with a Web service. Effective database security requires a strategy based on a full understanding of the security vulner-
abilities of SQL.

3. The typical organization lacks full-time database security personnel. The result is a mismatch between requirements and capabilities. Most organizations have a staff of database administrators, whose job is to manage the database to ensure availability, performance, correctness, and ease of use. Such administrators may have limited knowledge of security and little available time to master and apply security techniques. On the other hand, those responsible for security within an organization may have very limited understanding of database and DBMS technology.

4. Most enterprise environments consist of a heterogeneous mixture of database platforms (Oracle, IBM DB2 and Informix, Microsoft, Sybase, etc.), enterprise platforms (Oracle E-Business Suite, PeopleSoft, SAP, Siebel, etc.), and OS platforms (UNIX, Linux, z/OS, and Windows, etc.). This creates an additional complexity hurdle for security personnel.

An additional recent challenge for organizations is their increasing reliance on cloud technology to host part or all of the corporate database. This adds an additional burden to the security staff.

---

#### 2. Explain what is an SQL-injection attack and what are its “avenues”. Provide an example of an SQL-injection attack

The SQL injection (SQLi) attack is one of the most prevalent and dangerous network-based security threats. 

In general terms, an SQLi attack is designed to exploit the nature of Web application pages. In contrast to the static webpages of years gone by, most current websites have dynamic components and content. Many such pages ask for information, such as location, personal identity information, and credit card information.

This dynamic content is usually transferred to and from back-end databases that contain volumes of information—anything from cardholder data to which type of running shoes is most purchased. An application server webpage will make SQL queries to databases to send and receive information critical to making a positive user experience. In such an environment, an SQLi attack is designed to send malicious SQL commands to the database server. The most common attack goal is bulk extraction of data. Attackers can dump database tables with hundreds of thousands of customer records. Depending on the environment, SQL injection can also be exploited to modify or delete data, execute arbitrary operating system commands, or launch denial-of-service (DoS) attacks.

**A Typical SQLi Attack**

SQLi is an attack that exploits a security vulnerability occurring in the database layer of an application (such as queries). Using SQL injection, the attacker can extract or manipulate the Web application’s data. The attack is viable when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed, and thereby unexpectedly executed.

A typical example of an SQLi attack. The steps
involved are as follows:
1. Hacker finds a vulnerability in a custom Web application and injects an SQL
command to a database by sending the command to the Web server. The command is injected into traffic that will be accepted by the firewall.
2. The Web server receives the malicious code and sends it to the Web application server.
3. The Web application server receives the malicious code from the Web server and sends it to the database server.
4. The database server executes the malicious code on the database. The database returns data from credit cards table.
5. The Web application server dynamically generates a page with data including credit card details from the database.
6. The Web server sends the credit card details to the hacker.


---

#### 3. Advanced Persistent Threats

a particular concern is represented by advanced persistent threats
(APTs), well-resourced, persistent application of various intrusion technologies and malware to selected targets. They are typically attributed to state-sponsored organisations and criminal enterprises and differ from other attacks by their careful target selection and persistent, stealthy intrusion efforts over extended periods.

- **advanced** use a wide variety of intrusion technologies and malware including development of custom malware if required and the individual component may not necessarily be technically advanced but are carefully selected to suit the chosen target;

- **persistent** determined application of attacks over an extended period against the chosen target to maximize the chance of success and a variety of attacks may be progressively applied until the target is compromised;

- **threats**: threats to the selected targets as a result of the organised, capable and well-funded attackers' intent to compromise the specifically chosen targets, the active involvement of people in the prcess greatly raises the threa level from that due to automated attacks tools, and also the likelihood of successful attacks.

Variety of techniques: Social Engineering, Phishing, Software

Aims: Theft of intellectual property, physical/technical disruption

____

### 4. Virus vs Worm

##### **Virus**

Software that infects an executable host program and depends on the execution of that program

Components:

- Infection mechanism (copying itself into other executables/bootloader/documents with macros)

- Trigger (to switch from propagation to active phase)

- Payload (actualy malicious activity)

È composto da 4 fasi:

- fase dormente: il virus è nascosto e può essere attivato da qualche evento, è una fase non presente in tutti i virus;

- fase di propagazione: il virus si duplica all'interno di altri programmi o area di sistema nel disco. Ogni programma infetto ora contiene una copia del virus che entrerà essa stessa in fase di propagazione;

- fase di trigger: il virus viene attivato per eseguire le funzioni per cui è stato implementato, il trigger può essere innescato da una varietà di eventi di sistema;

- fase d'esecuzione: la funzione del virus viene eseguita

##### Worm

Indipendent program that operates autonomously looking over the Internet/Infected Systems to propagate

Propagation methods:

- Emails or Instant messages applications

- File Sharing

- Remote Access/Execution/Login Capabilities

Worm scanning phase possibilities:

- Random

- Predefined list of IPs (hit-list)

- Topological (looking for more hosts to scan inside an infected machine's data)

- Local Subnet (looking for infectable hosts inside a Network)

n.b They differ in **Propagation/Replication** but they share the same **Life Cycle** (Idle/Propagation/Activation/Execution)

Usa le stesse fasi di un virus normale, ma la fase di propagazione è composta da:

- scanning phase: una fase che cerca un meccanismo di accesso ad altri sistemi per infettarli;

- ricerca esaminando dati locali, come host table e address book, alla ricerca di indirizzi per possibili host target oppure cercare media device removibili.

- fase di trasferimento: il worm trasferisce una copia di se stesso su un sistema remoto e fa partire la fase di replicazione

La differenza principale con un virus è la modalità di attivazione e la fase di propagazione. Un virus necessita di un evento di sistema che inneschi il suo trigger per essere attivato, mentre un worm possiede un meccanismo automatizzato di attivazione. 

____

#### 5. Intrusion Detection

**Purposes**:

- Quickly act on ongoing intrusions to avoid escalation

- Deterring and preventing intrusions

- Gather intrusion info to strengthen the existing intrusion prevention measures

- High Detection Rates, Low False Positive Rates

**Classification**:

- **HIDS** (Host Based) - to determine intrusions within the host's OS

- **NIDS** (Network Based) - networking traffic monitoring

- **DIDS** (Distributed or Hybrid) - combining both Host based and Network based

**Methodologies**:

- **Anomaly Detection**: collection of data about users behaviours
  
  +Zero day attacks discoveries
  
  -Resource wasting into continuous data collection

- **Signature or Heuristic Detection**: comparing known malicious patterns with current data
  
  +Simple to deploy
  
  -cannot detect Zero day attacks

----

#### 6. Figure 5.1 SQLi attack schema

Quello in figura è il tipico schema di un SQL injection attack che tipicamente funziona terminando prematuramente una stringa utilizzando "--" come escape command e aggiungendo stringhe addizionali per l'esfiltrazione dei dati.

Un attaccante può implementare un SQLi attraverso:

- user input

- server variabe

- second-order injection: ovvero richiedere dati già presenti nel sistema per triggerare un SQL injection attack con questi dati

- cookies

- physical user input

---

#### 7. Figure 5.3 Inference

La figura riguarda lo schema del processo di inferenza, un problema che nasce quando dalla risposta di query legittime vengono estrapolate informazioni più sensibili della risposta stessa, magari combinando più risposte legittime. Due soluzioni sono a tempo di design del database e a tempo di query. La prima consiste nel capire quando potrebbe essere fatta inferenza sui dati che il database conterrà, la seconda consiste nell'eliminare un inference channel negando una query o modificandola in modo tale da non permettere esfiltrazione dei dati.

---

#### 8. Figure 5.6 range queries in encrypted DB

Le range query sono un metodo per rendere maggiormente utile i database cifrati e le encrypted query. Questo metodo consiste nel definire classi nelle quali gli attributi possono variare all'interno di un range, ad esempio per il salario craere una classe che ha diversi valori, magari uno compreso tra [60K, 79k] e così via. Ciò permette di variare maggiormente con le query e di trovare un trade off tra sicurezza ed efficienza nella cifratura dei database.
