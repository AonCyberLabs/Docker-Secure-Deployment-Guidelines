<html>

<head>
<h3>Docker Secure Deployment Guidelines</h3>
</head>

<body>

<p align="justify">
Within today’s growing cloud-based IT market, there is a strong demand for virtualisation technologies. Unfortunately most virtualisation solutions are not flexible enough to meet developer requirements and the overhead implied by the use of full virtualisation solutions becomes a burden on the scalability of the infrastructure. 
<br><br>
Docker reduces that overhead by allowing developers and system administrators to seamlessly deploy containers for applications and services required for business operations. However, because Docker leverages the same kernel as the host system to reduce the need for resources, containers can be exposed to significant security risks if not adequately configured.
<br><br>
The following itemised list suggests hardening actions that can be undertaken to improve the security posture of the containers within their respective environment. It should be noted that proposed solutions only apply to deployment of Linux Docker containers on Linux-based hosts, using the most recent release of Docker at the time of this writing (1.4.0, commit <code>4595d4f</code>, dating 11/12/14).
<br><br>
Part of the content below is based on publications from Jérôme Petazzoni<sup> [1]</sup> and Daniel J Walsh<sup> [2]</sup>. This document aims at adding on to their recommendations and how they can specifically be implemented within Docker.
<br><br>
<em>Note</em>: Most of suggested command line options can be stored and used in a similar manner inside a Dockerfile for automated image building.
</p>

<table tyle="width:100%">
  <tr>
    <th>Item</th>
    <th>Deployment</th> 
  </tr>
  <tr>
    <td valign="top">Docker Images</td>
    <td><p align="justify">Docker 1.3 now supports cryptographic signatures<sup> [3]</sup> to ascertain the origin and integrity of official repository images. This feature is however still a work in progress as Docker will issue a warning but not prevent the image from actually running. Furthermore, it does not apply to non-official images.
    <br>
    <br>
    In general, ensure that images are only retrieved from trusted repositories and that the <code>--insecure-registry=[]</code> command line option is never used.</td> 
  </tr>
  <tr>
    <td valign="top">Network Namespaces<sup> [4]</sup></td>
    <td><p align="justify">By default, the Docker REST API used to control containers exposed via the system Docker daemon is only accessible locally via a Unix domain socket.
    <br>
    <br>
    Running Docker on a TCP port (i.e. forcing the bind address using the -H option when launching the Docker daemon) will allow anyone with access to that port to gain access to the container, potentially gaining root access on the host as well in some scenarios where the local user belongs to the docker group<sup> [5]</sup>. 
    <br>
    <br>
    When allowing access to the daemon over TCP, ensure that communications are adequately encrypted using SSL<sup> [6]</sup> and access controls effectively prevent unauthorised parties from interacting with it.
    <br>
    <br>
    Kernel firewall iptables rules can be applied to <code>docker0</code>, the standard network bridge interface for Docker, to enforce those controls.
    <br>
    <br>
    For instance, the source IP range of a Docker container can be restricted from talking with the outside world using the following iptables filter<sup> [7]</sup>.
    <code>iptables -t filter -A FORWARD -s &lt;source_ip_range&gt; -j REJECT --reject-with icmp-admin-prohibited<code></p></td>
  </tr>
  <tr>
    <td valign="top">Logging & Auditing</td>
    <td><p align="justify">Collect and archive security logs relating to Docker for auditing and monitoring purposes.
    <br>
    <br>
    Accessing log files outside of the container, from the host<sup> [8]</sup>, can be performed using the following command:<br>
    <code>docker run -v /dev/log:/dev/log &lt;container_name&gt; /bin/sh</code>
    <br>
    <br>
    Using the Docker command built-in:<br>
    <code>docker logs ...</code>
    (-f to follow log output)
    <br>
    <br>
    Log files can also be exported for persistent storage into a tarball using:<br>
    <code>docker export ...</code></p></td>
  </tr>
  <tr>
    <td valign="top">SELinux or AppArmor</td>
    <td><p align="justify">Linux kernel security modules such as Security-Enhanced Linux (SELinux) and AppArmor can be configured, via access control security policies, to implement mandatory access controls (MAC) confining processes to a limited set of system resources or privileges.
    <br>
    <br>  
    SELinux can be enabled in the container using setenforce 1, if it was previously installed and configured. The SELinux support for the Docker daemon is disabled by default and needs to be enabled using <code>--selinux-enabled</code>.
    <br>
    <br>
    Introduced in Docker version 1.3<sup> [9]</sup>, label confinement for the container can be configured using the newly added <code>--security-opt</code>argument to load SELinux or AppArmor policies, as shown in the Docker <code>run</code> reference excerpt below.
    <br> 
    <code>--security-opt="label:user:USER"</code>   : Set the label user for the container<br>
    <code>--security-opt="label:role:ROLE"</code>   : Set the label role for the container<br>
    <code>--security-opt="label:type:TYPE"</code>   : Set the label type for the container<br>
    <code>--security-opt="label:level:LEVEL"</code> : Set the label level for the container<br>
    or<br>
    <code>--secutity-opt="apparmor:PROFILE"</code>  : Set the apparmor profile to be applied to the container</code>
    <br>
    <br>
    <em>Example:</em><br>
    <code>docker run --security-opt=label:level:s0:c100,c200 -i -t centos bash</code></p></td>
  </tr>
  <tr>
    <td valign="top">Daemon Privileges</td>
    <td><p align="justify">Do not use the <code>--privileged</code> command line option. This would otherwise allow the container to access all devices on the host and would in addition provide the container with specific a LSM (i.e SELinux or AppArmor) configuration that would give it the same level of access as processes running on the host.
    <br>
    <br>
    Avoiding the use of <code>--privileged</code> helps reduce the attack surface and potential of host compromise. This however does not mean that the daemon will run without root privileges which is still currently required in the latest release. 
    <br>
    <br>
    The ability to launch the daemon and containers should only be given to trusted user.
    <br>
    <br>
    Minimize privileges enforced inside the container by leveraging the -u option.<br>
    <em>Example:</em><br>
    <code>docker run -u &lt;username&gt; -it &lt;container_name&gt; /bin/bash</code> 
    <br><br>
    Any user part of the docker group could eventually get root on the host from the container</p></td>
  </tr>
  <tr>
    <td valign="top">cgroups<sup> [10]</sup></td>
    <td><p align="justify">In order to prevent Denial of Service (DoS) attacks via system resource exhaustion, a number of resource restrictions can be applied using specific command line arguments.
    <br>
    <br>
    CPU usage:<br>
    <code>docker run -it --rm --cpuset=0,1 -c 2 ...</code>
    <br>
    <br>
    Memory usage:<br>
    <code>docker run -it --rm -m 128m ...</code>
    <br>
    <br>
    Storage usage:<br>
    <code>docker -d --storage-opt dm.basesize=5G</code>
    <br>
    <br>
    Disk I/O:<br>
    Currently not supported by Docker. BlockIO* properties exposed via systemd can be leveraged to control disk usage quotas on supported operating systems.</p></td>
  </tr>
  <tr>
    <td valign="top">SUID/GUID binaries</td>
    <td><p align="justify">SUID and GUID binaries can prove dangerous when vulnerable to attacks leading to arbitrary code execution (e.g. buffer overflows), as they will be running under the context of the process’s file owner or group. 
    <br>
	<br>
    When possible, prohibit SUID and SGID from taking effect by reducing the capabilities given to containers using specific command line arguments.<br>
    <code>docker run -it --rm --cap-drop SETUID --cap-drop SETGID ...</code>
    <br>
    <br>
    Alternatively, consider removing SUID capabilities from the system by mounting filesystem with the <code>nosuid</code> attribute.
    <br>
    <br>    
    One last option could be to remove unwanted SUID and GUID binaries from the system altogether. These types of binaries can be found on a Linux system by running the following commands:<br>
    <code>find / -perm -4000 -exec ls -l {} \; 2>/dev/null</code><br>
    <code>find / -perm -2000 -exec ls -l {} \; 2>/dev/null</code>
    <br>
    <br>
    The SUID and GUID file permissions can then be removed using commands similar to the following<sup> [11]</sup>:<br>
    <code>sudo chmod u-s filename</code>
    <code>sudo chmod -R g-s directory</code></p></td>
  </tr>
  <tr>
    <td valign="top">Devices control group (/dev/*)</td>
    <td><p align="justify">If required, mount devices using the built-in <code>--device</code> option (do not use -v with the <code>--privileged</code> argument). This feature was introduced in  version 1.2<sup> [12]</sup>.
    <br>
    <br>
    <em>Example (for using sound card):</em><br>
    <code>docker run --device=/dev/snd:/dev/snd ...</code></p></td>
  </tr>
  <tr>
    <td valign="top">Services and Applications</td>
    <td><p align="justify">To reduce the potential for lateral movement if a Docker container was to be compromised, consider isolating sensitive services (e.g. run SSH service on bastion host or in a VM).
    <br>
    <br>
    Furthermore, do not run untrusted applications with root privileges within containers.</p></td>
  </tr>
  <tr>
    <td valign="top">Mount Points</td>
    <td><p align="justify">This is handled automatically by Docker when using the native container library (i.e. libcontainer). 
    <br>
    <br>
    However, when using the LXC container library, sensitive mount points should ideally be manually mounted with read-only permissions, including:<br>
    <code>/sys</code><br> 
    <code>/proc/sys</code><br>
    <code>/proc/sysrq-trigger</code><br> 
    <code>/proc/irq</code><br>
    <code>/proc/bus</code>
    <br>
    <br>
    Mount permissions should later be removed to prevent remounting.</p></td>
  </tr>
  <tr>
    <td valign="top">Linux Kernel</td>
    <td><p align="justify">Ensure kernel is up-to-date using update utility provided by the system (e.g. apt-get, yum, etc). Out-dated kernels are more likely to be vulnerable to publicly disclosed vulnerabilities.
    <br>
    <br>
    Use strengthened a kernel with GRSEC or PAX, that for example provide increased security against memory corruption bugs.</p></td>
  </tr>
  <tr>
    <td valign="top">User Namespaces</td>
    <td><p align="justify">Docker does not support user namespaces but is a feature currently under development<sup> [13]</sup>. UID mapping is currently supported by the LXC driver but not in the native libcontainer library.
    <br>
    <br>    
    This feature would allow the Docker daemon to run as an unprivileged user on the host but appear as running as root within containers.</p></td>
  </tr>
  <tr>
    <td valign="top">libseccomp (and seccomp-bpf extension)</td>
    <td><p align="justify">The libseccomp library allows restricting the use of Linux kernel’s syscall procedures based on a white-list approach. Syscall procedures not vital to system operation should ideally be disabled to prevent abuse or misuse within a compromised container.
    <br>
    <br>
    This feature is currently a work in progress (available in LXC driver, not in libcontainer which is now default).
    <br>
    <br>
    To restart the Docker daemon to use the LXC driver use<sup> [14]</sup>:<br>
    <code>docker -d -e lxc</code>
    <br>
    <br>
    Instructions on how to generate a seccomp configuration are on the Docker GitHub repository within the 'contrib'<sup> [15]</sup> folder. This can later be used to create a LXC based Docker container using the following command:<br>
    <code>docker run --lxc-conf="lxc.seccomp=$file" &lt;rest of arguments&gt;</code></p></td>
  </tr>
  <tr>
    <td valign="top"><code>capabilities(7)</code></td>
    <td><p align="justify">Drop linux capabilities to a minimum whenever possible.
    Docker default capabilities include: <code>chown</code>, <code>dac_override</code>, <code>fowner</code>, <code>kill</code>, <code>setgid</code>, <code>setuid</code>, <code>setpcap</code>, <code>net_bind_service</code>, <code>net_raw</code>, <code>sys_chroot</code>, <code>mknod</code>, <code>setfcap</code>, and <code>audit_write</code>.
    <br>
    <br>
    Can be controlled when launching a container from command line with <code>--cap-add=[]</code> or <code>--cap-drop=[]</code>. 
    <br>
    <br>
    <em>Example:</em><br>
    <code>docker run --cap-drop setuid --cap-drop setgid -ti &lt;container_name&gt; /bin/sh</code>
    <br>
    <br>
    This feature was introduced in Docker version 1.2<sup> [16]</sup></p></td>
  </tr>
  <tr>
    <td valign="top">Multi-tenancy Environments</td>
    <td><p align="justify">Due to the shared nature of Docker containers’ kernel, separation of duty in multi-tenancy environments cannot be achieved securely. It is recommended that containers be run on hosts that have no other purposes and are not used for sensitive operations. Consider moving all services into containers controlled by Docker.
    <br>
    <br> 
    When possible, keep inter-container communications to a minimum by setting the Docker daemon to use <code>--icc=false</code> and specify -link with docker run when necessary, or <code>--export=port</code> to expose a port from the container without publishing it on the host.
    <br>
    <br>
    Map groups of mutually-trusted containers to separate machines<sup> [17]</sup>.</p></td>
  </tr>
  <tr>
    <td valign="top">Full Virtualisation</td>
    <td><p align="justify">Use a full virtualisation solution to contain Docker, such as KVM. This will prevent escalation from the container to the host if a kernel vulnerability is exploited inside the Docker image.
    <br>
    <br>
    Docker images can be nested to provide this KVM virtualisation layer as shown in the Docker-in-Docker utility<sup> [18]</sup>.</p></td>
  </tr>
  <tr>
    <td valign="top">Security Audits</td>
    <td><p align="justify">Perform regular security audits of your host system and containers to identify mis-configuration or vulnerabilities that could expose your system to compromise.</p></td>
  </tr>
</table>

<h2>References</h2>
[1] <em>Docker, Linux Containers (LXC), and security</em> (August, 2014). Jérôme Petazzoni. [presentation slides]
http://www.slideshare.net/jpetazzo/docker-linux-containers-lxc-and-security
<br>[2] <em>Docker and SELinux</em> (July, 2014). Daniel Walsh [video]
https://www.youtube.com/watch?v=zWGFqMuEHdw
<br>[3] <em>Docker 1.3: Signed Images, Process Injection, Security Options, Mac shared directories</em> (October, 2014). Scott Johnston
http://blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/
<br>[4] <em>Exploring LXC Networking</em> (November, 2013). Milos Gajdos.
http://containerops.org/2013/11/19/lxc-networking/
<br>    <em>PaaS under the hood, episode 1: kernel namespaces</em> (November, 2012). Jérôme Petazzoni.
http://blog.dotcloud.com/under-the-hood-linux-kernels-on-dotcloud-part
<br>    <em>Exploring networking in Linux containers</em> (January, 2014). Milos Gajdos. [presentation slides]
https://speakerdeck.com/gyre007/exploring-networking-in-linux-containers
<br>[5] <em>How to grant rights to users to use Docker in Fedora</em> (October 2014). Daniel Walsh
http://opensource.com/business/14/10/docker-user-rights-fedora 
<br>[6] <em>Running Docker with https.</em> [Docker documentation]
https://docs.docker.com/articles/https/
<br>[7] <em>security suggestions when running malicious code</em>, Google Groups (August, 2013). Jérôme Petazzoni 
https://groups.google.com/forum/#!msg/docker-user/uuiQ3Nk3uSY/SuFpdO6BPmYJ
<br>[8] <em>Monitoring Images and Containers.</em> [Red Hat documentation]
https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Resource_Management_and_Linux_Containers_Guide/sec-Monitoring_Images.html
<br>[9] <em>Docker 1.3: Signed Images, Process Injection, Security Options, Mac shared directories</em> (October, 2014). Scott Johnston
http://blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/
<br>[10] <em>Resource management in Docker</em> (September, 2014). Marek Goldmann.
https://goldmann.pl/blog/2014/09/11/resource-management-in-docker/
<br>    <em>Gathering LXC and Docker Containers Metrics</em> (October, 2013). Jérôme Petazzoni.
http://blog.docker.com/2013/10/gathering-lxc-docker-containers-metrics/
<br>[11] <em>Removing SUID and SGID flags off binaries</em> (August, 2008). Eric Thern.
http://www.thern.org/projects/linux-lecture/intro-to-linux/node10.html
<br>[12] <em>Announcing Docker 1.2.0</em> (August, 2014). Victor Vieux.
http://blog.docker.com/2014/08/announcing-docker-1-2-0/
<br>[13] <em>Having non-root privileges on the host and root inside the container #2918</em> (November, 2013). [GitHub issue]
https://github.com/docker/docker/issues/2918
<br>    <em>Support for user namespaces #4572</em> (March 2014). [GitHub issue]
https://github.com/docker/docker/pull/4572
<br>    <em>Proposal: Support for user namespaces #7906</em> (September, 2014). [GitHub issue]
https://github.com/docker/docker/issues/7906
<br>    <em>Issue 8447: syscall, os/exec: Support for User Namespaces</em> (July, 2014) [Google Code issue]
https://code.google.com/p/go/issues/detail?id=8447
<br>[14] <em>Docker 0.9: Introducing Execution Drivers and libcontainer</em> (March, 2014). Solomon Hykes
http://blog.docker.com/2014/03/docker-0-9-introducing-execution-drivers-and-libcontainer/
<br>[15] A simple helper script to help people build seccomp profiles for Docker/LXC (November 2013). Martijn van Oosterhout.
https://github.com/docker/docker/blob/487a417d9fd074d0e78876072c7d1ebfd398ea7a/contrib/mkseccomp.pl
<br>    https://github.com/docker/docker/blob/487a417d9fd074d0e78876072c7d1ebfd398ea7a/contrib/mkseccomp.sample
<br>[16] <em>Announcing Docker 1.2.0</em> (August, 2014). Victor Vieux.
http://blog.docker.com/2014/08/announcing-docker-1-2-0/
<br>[17] <em>Docker Container Breakout Proof-of-Concept Exploit</em> (June, 2014). James Turnbull
http://blog.docker.com/2014/06/docker-container-breakout-proof-of-concept-exploit/
<br>[18] docker2docker GitHub repository. Jérôme Petazzoni.
https://github.com/jpetazzo/docker2docker
<br>
<h2>License</h2>
<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">Docker Secure Deployment Guidelines</span> by <a xmlns:cc="http://creativecommons.org/ns#" href="https://github.com/GDSSecurity/MAM-Security-Checklist" property="cc:attributionName" rel="cc:attributionURL">Gotham Digital Science</a> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.

</body>
</html>
