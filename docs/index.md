#Network Security

##Definition and Importance of Network Security

Network security refers to the set of measures and precautions taken to protect the integrity, confidentiality, and availability of computer networks and the data transmitted over them. 

It is the field of cybersecurity focused on protecting computer networks from threats. Network security has three chief aims: to prevent unauthorized access to network resources; to detect and stop cyberattacks and security breaches in progress; and to ensure that authorized users have secure access to the network resources they need, when they need them.

It involves the implementation of various technologies, strategies, and policies to safeguard against unauthorized access, attacks, and potential damage.

###Some Keywords

* Confidentiality: Protecting sensitive information from unauthorized access ensures that only authorized individuals can access and view the data.
* Integrity: Ensuring the accuracy and reliability of data by preventing unauthorized modification or tampering.
* Availability: Ensuring that network resources and services are consistently available to authorized users, preventing disruptions or downtime.
* Authentication: Verifying the identity of users and devices to ensure that only legitimate entities have access.
* Authorization: Controlling access to resources based on user permissions and roles.

##Common Network Security Attacks and Their Countermeasures

###Physical Attacks 

####Unauthorized Access 

The act of someone entering a physical space where computer systems, servers, networking equipment, or sensitive data are stored or processed, without the permission of the organization or individuals responsible for those resources. This could happen in various ways:

* Bypassing Physical Security Measures: Finding ways to circumvent physical security measures that protect the premises such as breaking locks, disabling alarms, or exploiting vulnerabilities in access control systems.
* Tailgating: Following closely behind an authorized individual to gain access to a secured area without using proper authentication methods.
* Social Engineering: Manipulating or deceiving individuals with legitimate access to the facility into providing them access by pretending to be a trusted person or using psychological tactics to trick employees.
* Insider Threats: Abusing their privileges as employees/contractors with legitimate access for intentionally or unintentionally allowing unauthorized individuals to enter secure areas. 

####Hardware Theft or Damage

The actions where an unauthorized individual deliberately takes servers, routers, switches, computers, or other network devices out of their assigned locations, destroys them, or impairs their ability to function. Some consequences of hardware theft or damage are:

* Data Loss: If stolen hardware contains sensitive data, its loss can lead to a compromise of confidential information.
* Service Disruption: Damage to critical network components can result in downtime by disrupting services and affecting operations
* Financial Loss: The cost of replacing stolen or damaged hardware, as well as the potential financial impact of business disruption, can be significant.

###Countermeasures of Physical Attacks

####Access Controls
Implementing secure physical access controls such as biometric scanners, card readers, and surveillance.

####Environmental Controls
Ensuring that data centers have adequate physical security, such as locked doors, security personnel, and secure enclosures.

####Backup and Redundancy 
Regularly backing up data and having redundant hardware to mitigate the impact of theft or damage.

###Software-Based Attacks

####Malware (Malicious Software)

An umbrella term includes a variety of harmful software types designed to disrupt, cause harm, exploit vulnerabilities, or gain unauthorized access to computer systems and data. Some types of malwares are:

* Viruses: Malwares that attach themselves to legitimate executable files in order to spread and infect other files when the infected program is executed.
* Worms: Malwares that replicate itself and spread across networks and systems by often exploiting vulnerabilities.
* Trojan Horses: Malwares disguised as legitimate software to trick users into installing it to perform a range of malicious activities.
* Spyware: Malwares designed to secretly collect and transmit user information without the consent of the user, often for advertising or identity theft purposes.
* Ransomware: Malwares that encrypt files on a victim's system and demand a ransom for the decryption key.
* Adware: Malwares that display unwanted advertisements, often installed along with legitimate software.

####Phishing

Type of social engineering attack where cybercriminals use fraudulent emails, messages, or websites to trick people into divulging sensitive information, such as usernames, passwords, credit card numbers, or other personal data.

Typically involves deceptive communication where attackers impersonate trustworthy organizations to establish a false sense of legitimacy and make it challenging for people to differentiate between real and fraudulent communications or use urgency and fear tactics and compel recipients to take immediate actions to avoid perceived consequences. 

####Zero-Day Exploits

Targets a security vulnerability that is not yet documented or acknowledged by the software vendor or security community. Since the vulnerability is unknown, there is no official patch available to fix the security flaw. Cybercriminals act fast to take advantage of this time window to gain unauthorized access, steal data, or install malware. "Zero-day" refers to the fact that there are zero days of protection between the discovery and the first attack.

###Countermeasures of Sofware-Based Attacks

####Antivirus Software

A security program designed to detect, prevent, and remove malicious software, including viruses, worms, trojan horses, and other types of malwares. Regular updates are essential to keep this database current and effective against the latest threats. The key functions of Antivirus Software are:

* Scanning: They regularly scan files, programs, and the overall system for known patterns or signatures of malicious code.
* Behavioral Analysis: They identify suspicious behavior that may indicate the presence of malware, even if the specific code is not yet recognized.
* Quarantine and Removal: They quarantine the infected files when malware is detected to prevent further spread and then remove or clean the malicious code.
* Real-Time Protection: They provide real-time protection, monitoring system activities as they occur and blocking or alerting users to potential threats.

There are some limitations of Antivirus Software since the traditional antivirus relies on known signatures, which may not detect new or zero-day threats and may occasionally produce false positives (incorrectly identifying safe files as threats) or false negatives (failing to detect actual threats). Combine antivirus software with other security measures, such as firewalls, intrusion detection/prevention systems, and user education, for a comprehensive defense strategy.

####User Education 
Training users to recognize and avoid phishing attempts.

####Patching and Updating 
Regularly updating software and systems to patch known vulnerabilities.

###Network-Based Attacks 

####Denial of Service (DoS) Attacks

Type of cyberattack that aims to disrupt the normal functioning of a computer system, network, or service by overwhelming it with an excessive amount of traffic, requests, or by exploiting vulnerabilities to exhaust its resources. Methods used in DoS Attacks are:

* Ping Flood: Sending a large number of ICMP (Internet Control Message Protocol) echo request packets to the target, overwhelming its ability to respond to legitimate requests.
* SYN/ACK Flood: Exploiting the three-way handshake process of TCP by sending a flood of SYN (synchronize) or ACK (acknowledge) packets to consume the target's resources.
* HTTP Flood: Overloading a web server by sending a massive number of HTTP requests, often using botnets or other distributed methods.
DNS Amplification: Exploiting misconfigured DNS servers to amplify the volume of traffic sent to the target, overwhelming its resources.

####Man-in-the-Middle (MitM) Attacks 

Type of cyberattack where an unauthorized third-party intercepts and possibly manipulates the communication between two parties without their knowledge. Methods used in MitM Attacks are:

* Packet Sniffing: Capturing and analyzing network traffic in order to obtain access to data that is being transmitted between two parties without encryption.
* DNS Spoofing: Manipulating the Domain Name System (DNS) to redirect visitors to fraudulent websites controlled by the attacker.
* Wi-Fi Eavesdropping: Intercepting communication on unsecured Wi-Fi networks, where data is transmitted unencrypted.
* SSL Stripping: Downgrading secure HTTPS connections to unencrypted HTTP, giving the attacker access to confidential data.
* Session Hijacking: Stealing or taking over an authenticated session to impersonate the authorized user during the communication.

###Countermeasures of Network-Based Attacks

####Firewalls

A network security device or software that acts as a barrier between a trusted internal network and untrusted external networks, such as the internet. Its primary purpose is to monitor, filter, and control incoming and outgoing network traffic based on predetermined security rules. Key functions of Firewalls are:

* Packet Filtering: Inspecting individual packets of data based on predetermined rules. Packets that meet the criteria defined in the rules are allowed to pass, while others are blocked.
* Stateful Inspection: Examining the context of the traffic to determine whether it is part of an established connection. 
* Proxying: Receiving requests from internal users, forward them to external servers on behalf of the users, and then relay the responses back to the users.
* Network Address Translation (NAT): Translating private internal IP addresses to a single public IP address, enhancing the security and privacy of internal networks.

####Intrusion Detection/Prevention Systems (IDS/IPS)

IDS: A security tool that analyzes network activities to look for indications of unauthorized access, security policy violations, or malicious activities. It generates alerts or notifications to initiate further investigation when suspicious activity is detected.

IPS: An advanced security tool that actively blocks possible security threats in addition to detecting them. This can involve automatically modifying firewall rules, blocking malicious traffic, or executing other preventive actions to stop an ongoing attack.

####Encryption

A fundamental cybersecurity practice that involves encoding data in a way that makes it unintelligible to unauthorized parties during transmission by using algorithms and cryptographic keys. This transformation ensures that even if intercepted, the data remains confidential and secure. Key components of Encryption are:

* Data in Transit: The information moving between two parties over a network.
* Ciphertext: The encrypted form of the data that is transmitted, appears as a random sequence of characters and is meaningless without the appropriate decryption key.
* Encryption Algorithm: A set of mathematical operations used to transform plaintext into ciphertext (AES, RSA, and Triple DES).
* Cryptographic Keys: Keys are used in the encryption and decryption processes. The encryption key transforms plaintext into ciphertext, and the decryption key reverses the process.

##Referances
Pawar, Mohan V., and J. Anuradha. "Network security and types of attacks in network." Procedia Computer Science 48 (2015): 503-506.

Deogirikar, Jyoti, and Amarsinh Vidhate. "Security attacks in IoT: A survey." 2017 International Conference on I-SMAC (IoT in Social, Mobile, Analytics and Cloud)(I-SMAC). IEEE, 2017.

Li, Bin, et al. "Mimic encryption system for network security." IEEE Access 6 (2018): 50468-50487.

##About Me
İzem Zaim

19290467

[Project on My Github] [https://github.com/izemz/Network-Security-Attacks-and-Countermeasures]

[https://github.com/izemz/Network-Security-Attacks-and-Countermeasures]: https://github.com/izemz/Network-Security-Attacks-and-Countermeasures
