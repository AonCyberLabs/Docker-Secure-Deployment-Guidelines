<html>

<head>
<h3>Docker Secure Deployment Guidelines</h3>
</head>

<body>

<p>
Within today’s growing cloud-based IT market, there is a strong demand for virtualization technologies. Unfortunately most virtualization solutions are not flexible enough to meet developer requirements and the overhead implied by the use of full virtualisation solutions becomes a burden on the scalability of the infrastructure. 

Docker reduces that overhead by allowing developers and system administrator to seamlessly deploy containers for applications and services required for the business operation. However, because Docker leverages the same kernel as the host system to reduce the need for resources, containers can be exposed to a great security risk if not adequately configured.

The following itemised list suggests hardening actions that can be undertaken to improve the security posture of the containers within their respective environment. It should be noted that proposed solutions only apply to deployment of Linux Docker containers on Linux-based hosts, using Docker most recent release at the time of this writing (1.3.1, commit <code>4e9bbfa</code>, dating 31/10/14).

Part of the content below is based on publications from Jérôme Petazzoni and Daniel J Walsh. This document aims at adding on to their recommendations and how they can specifically be implemented within Docker.

<em>Note</em>: Most of suggested command line options can be stored and used in a similar manner inside a Dockerfile for automated image building.
<p>

<table border="1" style="width:100%">
  <tr>
    <th>Item</th>
    <th>Deployment</th> 
  </tr>
  <tr>
    <td>Docker Images</td>
    <td>Docker 1.3 now supports cryptographic signature to ascertain the origin and integrity of official repositories images. This feature is however still a work in progress as Docker will issue a warning but not prevent the image from actually running. Furthermore, it does not apply to non-official images.
    <br>
    <br>
    In general, ensure that images are only retrieved from trusted repositories and that the <code>--insecure-registry=[]</code> command line option is never used.</td> 
  </tr>
  <tr>
    <td>Network Namespaces</td>
    <td>By default, the Docker REST API used to control containers exposed via the system Docker daemon is only accessible locally via a Unix domain socket.
    <br>
    <br>
    Running Docker on a TCP port (i.e. forcing the bind address using the -H option when launching the Docker daemon) will allow anyone with access to that port to gain access to the container, potentially gaining root access on the host as well in some scenarios where the local user belongs to the docker group. 
    <br>
    <br>
    When allowing access to the daemon over TCP, ensure that communications are adequately encrypted using SSL and access controls effectively prevent unauthorised parties from interacting with it.
    <br>
    <br>
    Kernel firewall iptables rules can be applied to docker0, the standard network bridge interface for Docker, to enforce those controls.
    <br>
    <br>
    For instance, the source IP range of a Docker container can be restricted from talking with the outside world using the following iptables filter.
    <code>iptables -t filter -A FORWARD -s &lt;source_ip_range&gt; -j REJECT --reject-with icmp-admin-prohibited<code></td>
  </tr>
  <tr>
    <td>Logging & Auditing</td>
    <td>Collect and archive security logs relating to Docker for auditing and monitoring purposes.
    <br>
    <br>
    Accessing log files outside of the container, from the host, can be performed using the following command:<br>
    <code>docker run -v /dev/log:/dev/log rhel7 /bin/sh</code>
    <br>
    <br>
    Using the Docker command built-in:<br>
    <code>docker logs ...</code>
    (-f to follow log output)
    <br>
    <br>
    Log files can also be exported for persistent storage into a tarball using:<br>
    <code>docker export ...</code></td>
  </tr>
  <tr>
    <td>SELinux or AppArmor</td>
    <td>Linux kernel security modules such as Security-Enhanced Linux (SELinux) and AppArmor can be configured, via access control security policies, to implement mandatory access controls (MAC) confining processes to a limited set of system resources or privileges.
    <br>
    <br>  
    SELinux can be enabled in the container using setenforce 1, if it was previously installed and configured. The SELinux support for the Docker daemon is disabled by default and needs to be enabled using <code>--selinux-enabled</code>.
    <br>
    <br>
    Label confinement for the container can be configured using the newly added <code>--security-opt</code> to load SELinux or AppArmor policies. This feature was introduced in Docker version 1.3.
    <br>
    <br>
    <em>Example:</em><br>
    <code>docker run --security-opt=secdriver:name:value -i -t centos \ bash</code></td>
  </tr>
  <tr>
    <td>Daemon Privileges</td>
    <td>Do not use the <code>--privileged</code> command line option. This would otherwise allow the container to access all devices on the host and would in addition provide the container with specific a LSM (i.e SELinux or AppArmor) configuration that would give it the same level of access as processes running on the host.
    <br>
    <br>
    Avoid the use <code>--privileged</code> helps reduce the attack surface and potential of host compromise. This however does not mean that the daemon will run without root privileges which is still currently required in the latest release. 
    <br>
    <br>
    The ability to launch the daemon and containers should only be given to trusted user.
    <br>
    <br>
    Minimize privileges enforced inside the container by leveraging the -u option.
    <em>Example:</em><br>
    <code>docker run -u <username> -it ubuntu /bin/bash</code> 

    Any user part of the docker group could eventually get root on the host from the container</td>
  </tr>
  <tr>
    <td>cgroups</td>
    <td>In order to prevent Denial of Service (does) attacks via system resources exhaustion, a number of resources restrictions can be applied using specific command line arguments.
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
    Currently not supported by Docker. BlockIO* properties exposed via systemd can be leveraged to control disk usage quotas on supported operating systems.</td>
  </tr>
  <tr>
    <td>SUID/GUID binaries</td>
    <td>SUID and GUID binaries can prove dangerous when vulnerable to attacks leading to arbitrary code execution (e.g. buffer overflows), as they will be running under the context of the process’s file owner or group. 
    <br>
    <br>
    When possible, consider removing SUID capabilities from the system and mount filesystem with the <code>nosuid</code> attribute.
    <br>
    <br>    
    Find SUID/GUID binaries can be found on a Linux  on the system by running the following commands:<br>
    <code>find / -perm -4000 -exec ls -l {} \; 2>/dev/null</code><br>
    <code>find / -perm -2000 -exec ls -l {} \; 2>/dev/null</code>
    <br>
    <br>
    The SUID and GUID file permissions can then be removed using commands similar to the following:<br>
    <code>sudo chmod u-s filename</code>
    <code>sudo chmod -R g-s directory</code></td>
  </tr>
  <tr>
    <td>Devices control group (/dev/*)</td>
    <td>If required, mount devices using the built-in <code>--device</code> option (do not use -v with the <code>--privileged</code> argument). This feature was introduced in  version 1.2.
    <br>
    <br>
    <em>Example (for using sound card):</em><br>
    <code>docker run --device=/dev/snd:/dev/snd ...</code></td>
  </tr>
  <tr>
    <td>Services and Application</td>
    <td>To reduce the potential for lateral movement if a Docker container was to be compromised, consider isolating sensitive services (e.g. run SSH service on bastion host or in a VM).
    <br>
    <br>
    Furthermore, do not run untrusted applications with root privileges within containers.</td>
  </tr>
  <tr>
    <td>Mount Points</td>
    <td>This is handled automatically by Docker when using the native container library (i.e. libcontainer). 
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
    Mount permissions should later be removed to prevent remounting.</td>
  </tr>
  <tr>
    <td>Linux Kernel</td>
    <td>Ensure kernel is up-to-date using update utility provided by the system (e.g. apt-get, yum, etc). Out-dated kernels are more likely to be vulnerable to publicly disclosed vulnerabilities.
    <br>
    <br>
    Use strengthened a kernel with GRSEC or PAX, that for example provide increased security against memory corruption bugs.</td>
  </tr>
  <tr>
    <td>User Namespaces</td>
    <td>Docker does not support user namespaces but is a feature currently under development. UID mapping is currently supported by the LXC driver but not in the native libcontainer library.
    <br>
    <br>    
    This feature would allow the Docker daemon to run as an unprivileged user on the host but appear as running as root within containers.</td>
  </tr>
  <tr>
    <td>libseccomp (and seccomp-bpf extension)</td>
    <td>The libseccomp library allows to restrict the use of Linux kernel’s syscall procedures based on a white-list approach. Syscall procedures not vital to the system operation should ideally be disabled to prevent abuse or misuse within a compromised container.
    <br>
    <br>
    This feature is currently a work in progress (available in LXC driver, not in libcontainer which is now default).
    <br>
    <br>
    To restart the Docker daemon to use the LXC driver use:<br>
    <code>docker -d -e lxc</code>
    <br>
    <br>
    Instructions on how to generate a seccomp configuration on Docker GitHub repository within the ‘contrib’ folder. This can later be used to create a LXC based Docker container using the following command:<br>
    <code>docker run --lxc-conf="lxc.seccomp=$file" &lt;rest of arguments&gt;</code></td>
  </tr>
  <tr>
    <td><code>capabilities(7)</code></td>
    <td>Drop linux capabilities to a minimum whenever possible.
    Docker default capabilities include: <code>chown</code>, <code>dac_override</code>, <code>fowner</code>, <code>kill</code>, <code>setgid</code>, <code>setuid</code>, <code>setpcap</code>, <code>net_bind_service</code>, <code>net_raw</code>, <code>sys_chroot</code>, <code>mknod</code>, <code>setfcap</code>, and <code>audit_write</code>.
    <br>
    <br>
    Can be controlled when launching a container from command line with <code>--cap-add=[]</code> or <code>--cap-drop=[]</code>. 
    <br>
    <br>
    <em>Example:</em><br>
    <code>docker run --cap-drop setuid --cap-drop setgid -ti rhel7 /bin/sh</code>
    <br>
    <br>
    This feature was introduced in Docker version 1.2</td>
  </tr>
  <tr>
    <td>Multi-tenancy Environments</td>
    <td>Due to the shared nature of Docker containers’ kernel, separation of duty in the multi-tenancy environments cannot be achieved securely. It is recommended that containers be run on host that have no other purposes and are not used for sensitive operations. Consider moving all services into containers controlled by Docker.
    <br>
    <br> 
    When possible, keep inter-container communications to a minimum by setting the Docker daemon to use <code>--icc=false</code> and specify -link with docker run when necessary, or <code>--export=port</code> to expose a port from the container without publishing it on the host.
    <br>
    <br>
    Map groups of mutually-trusted containers to separate machines.</td>
  </tr>
  <tr>
    <td>Full Virtualisation</td>
    <td>Use a full virtualisation solution to contain Docker, such as KVM. This will prevent escalation from the container to the host if a kernel vulnerability is exploited inside the Docker image.
    <br>
    <br>
    Docker images can be nested to provide this KVM virtualisation layer as shown in the Docker-in-Docker utility</td>
  </tr>
  <tr>
    <td>Security Audits</td>
    <td>Perform regular security audit of your host system and containers to identify mis-configuration or vulnerabilities that could expose your system to compromise.</td>
  </tr>
</table>

<h2 align="center">License</h2>
<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">Docker Secure Deployment Checklist</span> by <a xmlns:cc="http://creativecommons.org/ns#" href="https://github.com/GDSSecurity/MAM-Security-Checklist" property="cc:attributionName" rel="cc:attributionURL">Gotham Digital Science</a> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.

</body>
</html>