## Part 4

#### 1. Unix security model

Unix alla base del suo security model ha un'entità, lo user, e un gruppo. Ogni soggetto, o utente, viene associato ad un identificativo univoco nel sistema chiamato User ID ed appartiene ad un gruppo primario identificato da un Group ID. Un utente oltre che al suo gruppo primario può appartenere anche ad altri gruppi.

Con i comandi setUID ad setGID si intendono quei comandi che il sistema usa per modificare temporaneamente i diritti di un utente o di un gruppo in modo tale da potere eseguere operazioni con privilegi di amministratore.

Lo sticky bit è quel bit che se settato su una cartella impone che soltanto il proprietario dei file all'interno della cartella può rinominare, muovere o eliminare quel determinato file. Questo bit è molto utile nelle cartelle condivise.

----

#### 2. Potential vulnerability of setUID

L'uso non appropriato di comandi setUID possono portare a privilege escalation con l'acquisizione di privilegi di root.

---

#### 3. Chroot jail

Restringe la vista del server del file sistem solo ad una porzione specifica. Le directory fuori dal chroot jail non sono visibili o raggiungibili. Se un cracker rompe un'applicazione chroot, deve rompere anche il jail prima di danneggiare il resto del sistema. Lo svantaggio principale è l'aggiunta di complessità, anche perché alcuni programmi non sono eseguiti sotto chroot.

---

#### 4. Windows Security Model

Windows uses the combination of DACL and MAC, which operates as in an AND condition

**1. DACL** (Discretionary Access Control List)

Implementing access control through checking the **SID** of the requesting user and its **access rights**

*Each SID had a list of access rights for each files he can access*

Discretionary because having the access rights on a file also makes it possible to grant those rights to other users

**2. MAC** (Mandatory Access Control)

Implemented in terms of **Integrity Levels**, which are determined for each Resource and User by the OS.

Access is granted only if:
`integrity level of the requesting User is >= to the one of the requested Resource`

n.b. MAC is performed **BEFORE** DAC, in a cascading way.

Windows also provides:

- Native support for **Filesystem Encryption**

- **Address-space Randomization** (buffer overflow defense)

- Mechanisms to **prevent code execution**

- **Control-Flow Guard** to prevent direct call to assembly code

- **Arbitrary Code Guard** to grant code authentication

- **Windows Defender Exploit Guard and Application Control** to authenticate applications before running them

- **Windows Defender Credential Guard** to grand user credential security

---

#### 5. Windows Security Components

###### 1. Security Reference Monitor

Implements Access Control

Each Process has a security **Token** that contains the identity of the **User** assiciated to it.
If a Process requests acces to an Object, the SRM checks if the Object's ACL contains the User's rights.

+SRM also performs **Logging** on each request and access, to register security events.

###### 2. Local Security Authority

Defines **Security Policies** (on passwords and auditing) and supports authentication.

LSA is the one that provides User's Tokens that will be given to each process that that User will spawn.

###### 3. Security Account Manager

Database that contains the Users Indentities and Passwords in an encrypted way.

It is just related to **Local Users**, which are the user that only belong to a particular machine.

###### 4. Active Directory

Provides credentials for a **Network's Users** (example: Organization Intranet) and implements LDAP (Lightweight directory access protocol)

It decentralizes the managament of the users for the system manager, identifying Users through their Security ID (**SID**)

---

#### 6. Windows Integrity Levels

Each User or Object is limited by his Integrity Level, which can be of 4 types:

- Low 

- Medium - default Level

- High

- System

some additional Rules:

- If a User executes a file, the new process will have the minumum integrity among the User's and the File's one
  +important for admin level executions

- If a User executes a non trusted file, it will be done in low Integrity Level as a precation measure first

Integrity Levels can be seen as a sort of **Sandboxing Method**:

The default Browser Microsoft Edge is flagged as Low Integrity Level, while the rest of the OS processes is run at medium/high level.
This is due to the fact that it may execute automatic website scripts that cannot be trusted by default.

---

#### 7. Byzantine Generals Problem

###### Original Formulation

n generals need to reach consensus on either attacking or retreating from battle.

The plan will fail only if some generals will attack and some others to retreat (with a traitor general convincing another one to retreat with him)

###### Simplified Version

**1** ***Commanding*** General + **n-1** ***Liutenant*** Generals

The Commander takes a decision, if **all** the Liutenants obey the plan succeeds, and it fails otherwise.

Also its important to know that:

- **Any** General can be a traitor

- if the Commanding one is the traitor, he could send different messages to different Liutenants

<u>To solve the problem</u> there is the need to guarantee 2 properties:

1. **Consensus**: guaranteeing that **all loyal liutenants will obey to the same order**.

2. **Validity**: if the **Commandin general is loyal**, then **each loyal liutenant obeys to his order**.

<u>Assuming that</u>:

- There are **m** **Traitors**

- Reliable Communications: messages are sent/delivered correctly

- Authenticated Dispatches: receiver knows sender's identity

- Synchronous Communications: dispatch is never delayed

Under these assumptions, there is <u>no solution</u> for $n ≤ 3m$ and there is <u>always a solution </u>for $n ≥ 3m+1$

<u>**Solving Algorithm**</u>:

1. Commanding general sends n-1 messages

2. Each Liutenant:
   
   - if receives no command -> assumes Retreat
   
   - Forwards command to n-2 liutenants
   
   - Receives n-2 commands from liutenants
   
   - evaluates the majority of the commands and acts on this result

Total number of dispatches: **O(**$n^2$**)**

---

#### 7. Blockchains Vulnerabilities & Attacks

- **51% Attacks**
  An entity or a Group controls more than 50% of the network's mining power of a POW Blockchain.
  They can potentially manipulate the chain controlling the consensus mechanism, double spending money and not allowing transactions.

- **Sybil Attacks**
  Malicious actor creates multiple fake nodes to gain control over a significant portion of the network, especially effective against POS blockchains.

- **Private Keys**
  Losing a the private key of an account also means losing the wallet and all of its associated cryptocurrencies

- **Double Spending**
  A user spends the same amount of cryptocurrencies twice, effectively creating a duplicate and fraudulent transaction.
  Can be performed in various ways, for example:
  
  - **Finney's Attack**:
    Attacker produces a "Solo" Block, with a single transaction to himself, without broadcasting it yet.
    Issue another transaction with another User, with the same quantity as the Solo Block.
    When the goods are delivered both the Solo Block and the other one are broadcasted, and the attacker has a 50% chance that the Solo Block gets picked for approval, accomplishing the Double Spending.
  
  - **Vector76 Attack**:
    Attacker produces a "Solo" Block **b1** containing the transaction with another user and then waits for another user to produce another b1 block, called **b1'** (they have the same precedessor block **b0**). At this point the attacker broadcasts his block **b1**, that will be discarded due to the presence of **b1'**, making the transaction refunded.
  
  - **Rosenfeld's Attack**:
    
    Attacker issues a transaction with another user. The user waits for the block commit, waiting for a series of block to be appended after it. The attacker builds a chain of Solo Blocks longer than the real appended serie, and commits it. Again here there is a chance that the Attacker's blockchain gets approved and the money refunded.
  
  ---
  
  #### 8. Figure 13.1 Virtual trust level
  
  I componenti di sistema ad ogni livello operano in base a livelli di privilegio specifici. Dietro a kernel mode e user mode, sfruttando la virtualizzazione (Hyper-V) per implementare un virtual trust level. Ci sono due trust level, ognuno dei quali può essere eseguito in kernel mode o user mode. Questi trust level sono chiamati normal world (VTL0) e secure world (VTL 1). Questo isola VTL0 da VTL1. Il secure world ha anche un kernel sicuro e una modalità utente isolata dove i processi fidati (trustlets) vengono eseguiti. L'hypervisor però viene eseguito in una modalità processore speciale (VMX/VT-x Root mode su processori Intel)

-----

#### 9. Figure 13.2 Windows login

L'immagine rappresenta la procedura di login di Windows, attraverso l'uso di SAM (Security Account Manager) oppure grazie a Active Directory (AD).

Quando un utente esegue il login correttamente, AD fornisce un token di autenticazione (security/access token). Questo token include: SID (session ID), gruppi (idenficati anche loro da SID), privilegi. Il token viene poi assegnato ad ogni processo eseguito dall'utente, è necessario eseguire l'access control quando un processo apre un oggetto. 

Invece, la Local Security Authority (LSA), quando viene effettuato un log in con successo, genera un token di autenticazione come il precedente. Da notare, come l'utente deve avere già un account locale e una password (opzionale). La password è opzionale perché in alcune impostazioni l'utente vuole evitare potential security issue, ma senza password non è consentito l'accesso da remoto e in qualsiasi caso l'admin deve avere una password.

La password è sempre consigliata in fase di setup e per gli account di dominio (AD) è obbligatoria.

---

#### 10. Privilege in Windows

I privilegi in Windows sono autorizzazioni a livello di sistema assegnate agli account utente, sono necessari per controllare le risorse di sistema e i task system-related dove i diritti di accesso e le ACL controllano l'accesso a oggetti sicuri ad esempio backup del computer, change system time. Alcuni privilegi sono considerati "benigni", ad esempio, "bypass traverse checking privilege" che permette di attraversare le directory anche se l'utente potrebbe non avere il permesso nelle directory attraversate.

Altri privilegi invece sono considerati "pericolosi" come:

- operare come parte dei privilegi di sistema operativo: TCB privilege che sono garantisce di eseguire come la parte più sicura del sistema, la parte più pericolosa in Windows che è garantita soltanto a Local System Account;

- debug program privilege: permette di debuggare ogni programma in windows, normalmente cosa che non è richiesta dagli utenti. Implica l'abilità di eseguire qualsiasi codice in ogni processo running;

- backup file and directories privilege: richiede l'accesso all'intero file system bypassando l'access control, può anche ripristinare file e directory dove è necessario bypassare il controllo degli accessi ed è pericoloso

---

#### 11. Security descriptor

I security descriptor sono una struttura dati che contiene proprietario dell'oggetto, gruppo, DACL e SACL (se presente). Ogni securable object, ovvero ogni risorsa del sistema che necessita di protezione, ha il proprio SD.

```
Owner: CORP\Blake
Group: CORP\Clerks
ACE[0]: Allow CORP\Blake Full_Control
ACE[1]: Allow CORP\Paige Full_Control
ACE[2]: Allow Administrators Full_Control
ACE[3]: Allow CORP\Cheryl Read, Write, Delete
```

Questo SD da il pieno controllo all'utente Blake, a Paige e agli amministratori. Nelle versioni più recenti di Windows è possibile limitare il full control dell'utente e anche il proprietario stesso può essere includo nella DACL. Non c'è un accesso implicito, se non ci sono ACE per l'utente, allora l'accesso all'oggetto da parte di processi di quell'utente viene negato. I processi devono richiedere il tipo di accesso corretto, se la richiesta è "all access" quando necessita meno, e quando non tutti sono permessi allora l'accesso viene negato.
