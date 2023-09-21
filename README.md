# Applied Security Laboratory

## What we did

We split in teams and were tasked with creating a certificate authority system for an imaginary company using VMs, complete composed of 4 main components - Web server that provides the user portal, a certificate authority server that issues/revokes certificates, a SQL server for data storage and a server for data backup.

The goal was to design a secure system, while leaving 2 back doors - one easy to find, and one tougher to find. Then, teams exchanged VMs, and performed pentests on eachother's systems.

## My role

Apart from designing and building the system alongside my teammates, I designed and implemented the backdoors, and then carried out the penetration testing on the other team's system (I got a bit carried away a ***bit*** more than 2 backdoors).

## Contents

- [backdoors-design](./backdoors-design/) - Explanation of the backdoors I designed to put in our system, as well as the scripts and steps necessary to exploit them
- [red-team-writeup](./red-team-writeup/) - My findings from running a pentest and code review on the other team's system
