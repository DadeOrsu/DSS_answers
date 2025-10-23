## Parte 3

#### 1. Shellcode in Buffer Overflow

In a buffer overflow attack, shellcode plays a crucial role as it is the **malicious code** injected into a vulnerable program's memory through an exploited buffer overflow vulnerability. 

**Purpose** =  take control of the compromised system by executing arbitrary commands, typically spawning a shell

n.b. Shellcode is **Architecture** and **OS Specific**

**Restrictions**

- **Position indipendence**
  it should work regardless to the position it will be placed (in the memory/stack)

- **Cannot invoke Library functions**
  Library functions may be located in different places depending on the attacked OS
  +Using them would compromise the Stack that we are already manipulating

- **No NULL Chars**
  Cannot risk the termination of the code with NULL or '\0' characters

---

#### 2. Buffer Overflow Defenses

**Compile-Time Defenses**

###### 1. Random Canary (also named StackGuard)

GCC extension to protect against overwrites of the stack return address.

Each time a function is invoked:

- Generation of a random number (needs to be actually random each time)

- Push of the random number into the Stack before allocating any other function variable

- Copy of the random number into a safe memory (Heap)

When the function returns:

- Comparison of the Stack canary value with the Heap one:
  equal = no corruption / corrupted otherwise

n.b. it can generate compile time overhead and debugger problems

###### 2. StackShield and Return Address Defender

GCC extension that doesn't alter the Stack frame, but only keeps a copy of the return address to compare it with the after function call return address.

**Run-Time Defenses**

###### 3. Executable Address Space Protection

Blocking the execution of code on the Stack, through MMU support on virtual memory flagging

+no recompilation of code

-some programs may need to execute code on the Stack

###### 4. Address Space Randomisation

When writing a program into the memory, the OS picks a random initial Stack Address each time the program is executed, making it impossible for the attacker to prepare an ad-hoc shellcode to retrieve the stack pointer.

###### 5. Guard Pages

Allocating Guard pages in between the old Stack Pointer and the local variables of a function call.
The guard pages are marked as **not accessible**, so any attempt of overwriting them will result in execution abortion.

---

#### 3.  Software security, quality and reliability

###### Quality and Reliability

Focus on creating software that is robust, bug-free, capable of completing its tasks.

Problems: Accidental failure of a program due to random inputs, unexpected situations and bad coding practices.

###### Security

Preventing accidental/not failures due to **external** factors, through structured developing and pentesting.

It involves developing countermeasures to harmful exploits generating vulnerability resilient software.

____

#### 4. Defensive Programming

**Objective**: Designing and implementing software so that it continues to function even when under attack

Need of attention on every aspect of program execution (Environment, Data types), without taking anything for granted, handling any possible error state.

Programmers often make assumptions about the nature of the inputs a program will
receive and the environment in which it will run, but these assumptions must be validated by the program and any potential failures must be handled gracefully and safely. Need to reduce the probability of vulnerability presence and reducing their exploitation impact.

---

#### 5. Windows OS Hardening

Security Development Lifecycle (checklist on component developing):

- Mandatory cysec education

- Security design requirements

- Threat modeling

- Attack surface analysis and reduction

- Secure coding/testing requirements and tools

- Final security review

- Security response plans

It is a technique also known as attack surface reduction and it use the 80/20 rule: if a functionality isn't used by the 80% of users, it should be deleted (hard in general purpose OSs) but it is not always achievable since it may result in a system not usable for non-technical users.

---

#### 6. Protection methods

#### Syscall Filtering

Additional level of control of syscalls (apart from Kernel protection)

It can limit the syscall types that processes can call while inspecting the passed arguments.

Can be implemented in various ways, including: **Whitelisting** (list of allowed syscalls), **Blacklisting** (list of prohibited syscalls), **Dynamic Filtering** (with dynamically changing rules based on program's behaviour)

- examples: Linux Fast Mutex (Futex), Berkley packet filtering

#### Sandbox

Running a process in a constrained environment, limiting its syscalls and its access to resources.

- examples: Java implements sandboxing at level of JVM, Android using Linux syscall filtering + MAC (mandatory access control)

#### Code Signing

Crypto Hashing code to ensure the executable is exactly the same as the developer's source.

Integrity is always granted since any change would alter the developer's signature (hash).

- Can also be used to disable obsolete programs, invalidating their signature.

#### Language-based Protection

Protection of compiled code through high-level policy descriptions and allocation of resources

example: **Java Compiler + JVM Runtime**
Mapping of language specific protection mechanisms to whatever OS and hardware is running the program, through:

- type safety (load and run-time checks)

- class encapsulation

- JVM stack inspection for syscalls invokations

---

#### 7. Virtualisation Security

It is all about Hypervisor security, since it's the hypervisor that controls virtualised resources, the guest OSs and their operation.

Each VM is independent and protected from each other, since they have their own virtual "physical" hardware. 

**Hypervisor Types**:

- Type 0: Firmware level Hypervisor

- Type 1: Hypervisor Virtualization implemented directly on hardware (VMWare, Oracle VM Server)

- Type 2: Hypervisor run over OS (VirtualBox, Parallels)

---

#### 8. Figure 6.1 fgets buffer overflow

Una doppia vulnerabilità di buffer overflow, dovuta sia all'uso di fgets che a quello di sprintf. fgets impone un controllo sulla size da leggere, ma in questo caso questa dipende dall'implementazione del chiamante e può essere soggetta a tampering. In più se vengono letti più di 16 caratteri in questo specifico caso viene sovrascritta comunque la memoria successiva. 

Mentre sprintf non pone un controllo sulla lunghezza dei dati da inserire dentro temp, di conseguenza se la lunghezza di val sommata a quella della stringa "read : %s\n" supera 16 allora avremo buffer overflow con sovrascrittura del valore di val e old frame pointer.

---

#### 9. Figure 6.6

L'immagine riguarda la modifica da parte di un rootkit della system call table, con la quale un attaccante può ottenere i privilegi di root/amministratore all'esecuzione di una fork per la creazione di un nuovo processo.

----

#### 10. Figure 6.7

---

#### 11. Figure 6.8 Honeypot system deployment

Un honeypot è un meccanismo di sicurezza creato per attirare, rilevare e analizzare i cyberattacchi. Si tratta di un sistema esca o di una risorsa di rete resa intenzionalmente vulnerabile per attirare gli aggressori, apparendo come un obiettivo legittimo. Le honeypot aiutano i team di sicurezza a conoscere il comportamento, gli strumenti e le tecniche degli aggressori senza mettere a rischio i sistemi reali.

Abbiamo due diversi tipi di honeypot:

- Low interaction honeypot: pacchetto software che emula particolari servizi IT o sistemi abbastanza bene da fornire un'interazione iniziale realistica, ma non esegue una versione completa di questi servizi o sistemi. Risulta essere un obiettivo meno realistico. È però spesso utile nell'implementazione di IDS distribuiti.

- High interaction honeypot: un sistema reale con un sistema operativo completo, servizi e applicazioni, che sono deployati dove possono essere acceduti dagli attaccanti. Questo tipo di honeypot è un target maggiormente realistico e può occupare  un attaccante per un periodo di tempo esteso ma richiede risorse significative per la sua implementazione.

----

#### 12. Figure 10.1 Hypervisor types

La figura riguarda i diversi tipi di hypervisor disponibili:

- type 0: questo tipo viene implementato interamente a livello firmware della CPU, il sistema operativo viene installato come guest host. Offre un piccolo insieme di funzionalità e spesso è basato su partizionamento fisico delle risorse hw. Inoltre può fornire virtualizzazione nella virtualizzazione;

- type 1: viene usato comunemente nei datacenter, spesso viene visto come il sistema operativo di tali datacenter. Spesso sono sistemi operativi special purpose che vengono eseguiti in bare metal, in altri datacenter invece sono sistemi operativi general purpose che offrono anche capacità di virtualizzazione. Viene eseguito in kernel mode e implementa i driver del device per l'hardware che hosta il servizio. 
  
  Vantaggi:
  
  - i manager dei datacenter possono controllare e gestire diversi guest os in un modo semplice e sofisticato, soltanto agendo sull'hypervisor;
  
  - Consente di consolidare i sistemi operativi e le applicazioni su meno HW.
  
  - Muove i guest tra i sistemi per bilanciare le performance;
  
  - permette lo snapshotting e il cloning

- type 2: non c'è coinvolgimento dell'OS dell'host nella virtualizzazione, la macchina virtuale è soltanto uno dei processi gestiti dal sistema operativo dell'host. Questo tipo di hypervisor hanno molte limitazioni:
  
  - le macchine virtuali vengono eseguite senza privilegi speciali;
  
  - in alcuni casi non ci sono vantaggi di caratteristiche specifiche dell'HW per la virtualizzazione;
  
  - performance molto basse;
  
  Ma ci sono anche alcuni vantaggi:
  
  - non richiedono nessun cambiamento al sistema operativo dell'host
  
  - facile da deployare e usare

---

#### 13. Figure 10.2 Trap and emulate mechanism

Il meccanismo trap and emulate permette ad un sistema virtualizzato di eseguire in modo safe istruzioni con privilegi senza compromettere direttamente il sistema operativo dell'host o l'hardware.

La CPU possiede due stati diversi, user e kernel mode. 

Il Sistema operativo dell'host viene eseguito in kernel mode, mentre i sistemi operativi ospiti (guest OS) vengono eseguiti in user mode, ma nonostante questo, il kernel ospite crede di essere eseguito in kernel mode ed esegue istruzioni con privilegi e si aspetta accesso libero in memoria, cosa che invece non deve essere consentita per un sistema ospite.

Per questo motivo il VM player installa un kernel driver nel kernel dell'host, richiede i privilegi di amministratore, modifica la tabella delle interruzioni per redirigere gli handler al supporto per la virtualizzazione. Se l'interrupt è per una VM allora viene fatta una upcall, altrimenti se è per un altro processo viene reinstallata la tabella degli interrupt e viene ripreso il kernel.

In questo modo il sistema operativo guest lavora sia in "virtual" user mode, che in "kernel" user mode, ma entrambi lavorano effettivamente in user mode nel sistema operativo dell'host. Le operazioni nella modalità kernel virtuale sono emulate in modalità kernel dal sistema operativo host per mezzo di una struttura di dati (virtual CPU).

Processi eseguiti in virtual user mode -> no problem

Quando invece un processo deve switchare in virtual kernel mode allora il processo prova ad eseguire un'operazione privileged -> trap, il processo viola la protezione -> trap, un processo invoca una system call al guest kernel -> trap. In questi casi il kernel dell'host prende il controllo, analizza i motivi del trap ed esegue le operazioni privilegiate richieste dal processo guest, poi ritorna il controllo al sistema guest in user mode

trap = interrupt

---

#### 14. Figure 10.3 Hardware support for virtualization

La figura mostra il meccanismo di trap and emulate utilizzato con il supporto hardware per la virtualizzazione. Questa modalità fornisce supporto per evitare la necessità di binary translation, introduce modalità di CPU aggiuntive (guest mode/host mode) e DMA. L'hypervisor può settare le caratteristiche della virtual machine associate ad ogni OS ospite, associare ad ogni guest la propria VCPU e passare un guest mode per eseguire il guest. Il sistema operativo guest in modalità guest pensa di essere in esecuzione nativa e vede la macchina virtuale specificata dall'hypervisor. Se tenta di accedere a un dispositivo virtualizzato → trap per l'hypervisor.

Con maggior dettaglio la figura riguarda la gestione di system call in modo efficiente da parte del meccanismo trap and emulate. Una volta che un processo in user mode del guest OS invoca una system call questo causa il passaggio da user mode a kernel mode all'interno del guest OS. Nel caso in cui questa operazione richieda privilegi il controllo passa al kernel del sistema operativo host o all'hypervisor che gestisce la chiamata tramite trap utilizzando gli interrupt vector allocati su una VCPU specifica per quel sistema operativo. Dopodiché il sistema operativo emula la chiamata di sistema e restituisce il controllo al guest OS che torna un user mode.

---

#### 15. Figure 10.4 Real time migration

La real time migration è un vantaggio di un guest OS che non può essere offerto da un host OS. Un intero guest OS può essere duplicato su un'altra macchina fisica oppure su un'altra macchina virtuale senza interrompere l'esecuzione del guest OS e delle sue applicazioni.

Funziona come di seguito:

1. la VM sorgente richiede una migrazione ad una VM target che crea un nuovo guest allocando VCPU, memoria, disco e I/O;

2. la sorgente invia al target tutte le pagine di memoria read-only del guest OS;

3. la sorgente invia al target tutte le pagine di memoria read-write del guest OS, segnandole come clean (pulite);

4. viene ripetutto lo step precedente perché durante la sua esecuzione alcune pagine possono essere state modificate e quindi sono diventate dirty;

5. Quando solo poche pagine sono dirty, sotto un determinato threshold, allora la sorgente congela il guest, invia lo stato della VCPU e ogni altro dettaglio di stato al target, infine manda le poche pagine dirty rimaneneti. A quel punto il target comincia ad eseguire il guest e la sorgente può essere uccisa.
