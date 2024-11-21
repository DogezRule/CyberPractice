Here’s a detailed **README file** with all the instructions, commands, and configurations included for easy copy-and-paste usage. It guides you through setting up the CyberPatriot practice image with Aeacus scoring.

---

# CyberPatriot Practice Image Setup with Aeacus

This guide walks you through creating a CyberPatriot practice environment using Aeacus as the scoring engine. Follow the steps below to configure the VM, set up vulnerabilities, and install the scoring engine.

---

## **1. Prepare the Virtual Machine**
1. Install **Ubuntu Server 20.04** on your virtualization platform (e.g., VirtualBox, VMware, Proxmox).
2. Update the system:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
3. Install essential tools:
   ```bash
   sudo apt install -y curl wget unzip net-tools
   ```

---

## **2. Set Up the Practice Image**

### **Step 1: Create the Setup Script**
1. Save the following script as `cyberpatriot_setup.sh`:
   ```bash
   nano cyberpatriot_setup.sh
   ```

2. Copy and paste the following script into the file:
   ```bash
   #!/bin/bash

   # Check for root privileges
   if [[ $EUID -ne 0 ]]; then
       echo "This script must be run as root."
       exit 1
   fi

   # Update system
   apt update -y && apt upgrade -y

   # Install essential software
   echo "Installing software..."
   apt install -y apache2 openssh-server samba mysql-server php7.4 netcat bsdgames curl wget unzip

   # Create Users
   echo "Creating users..."
   users=("student1" "student2" "teacher1" "admin" "hacker" "guest" "test" "backup" "temp" "shared" "testuser1" "testuser2" "backdoor" "unsecured" "hiddenuser")
   for user in "${users[@]}"; do
       adduser --disabled-password --gecos "" $user
       echo "$user:12345" | chpasswd
   done

   # Group Permissions
   echo "Configuring groups..."
   usermod -aG sudo admin
   usermod -aG sudo teacher1
   usermod -aG admin hacker
   usermod -aG sudo backdoor
   usermod -aG admin hiddenuser

   # Vulnerabilities
   echo "Introducing vulnerabilities..."

   # Weak passwords
   echo "admin:123456" | chpasswd
   echo "teacher1:password" | chpasswd
   echo "eviluser1:123" | chpasswd
   echo "unauthadmin:admin" | chpasswd

   # SSH Vulnerabilities
   echo "HostKeyAlgorithms +ssh-rsa" >> /etc/ssh/sshd_config
   echo "KexAlgorithms diffie-hellman-group1-sha1" >> /etc/ssh/sshd_config
   mkdir -p /home/testuser1/.ssh
   echo "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAtestweakkey" > /home/testuser1/.ssh/authorized_keys
   chmod 600 /home/testuser1/.ssh/authorized_keys
   chown -R testuser1:testuser1 /home/testuser1/.ssh
   chmod 777 /etc/ssh/sshd_config

   # Apache Directory Traversal
   mkdir -p /var/www/html/uploads
   chmod 777 /var/www/html/uploads
   echo "<?php echo shell_exec(\$_GET['cmd']); ?>" > /var/www/html/uploads/exploit.php
   systemctl restart apache2

   # Samba Misconfigurations
   mkdir -p /srv/samba/public
   chmod 777 /srv/samba/public
   echo "[Public]
       path = /srv/samba/public
       browseable = yes
       writable = yes
       guest ok = yes" >> /etc/samba/smb.conf
   systemctl restart smbd

   # MySQL Vulnerabilities
   mysql -e "CREATE DATABASE vulnerable_db;"
   mysql -e "CREATE USER 'vuln_user'@'%' IDENTIFIED BY 'weakpassword';"
   mysql -e "GRANT ALL PRIVILEGES ON vulnerable_db.* TO 'vuln_user'@'%';"
   mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '';"
   mysql -e "FLUSH PRIVILEGES;"

   # Fake Services
   echo "[Unit]
   Description=Fake Backup Service
   [Service]
   ExecStart=/usr/bin/fakebackup.sh
   [Install]
   WantedBy=multi-user.target" > /etc/systemd/system/fakebackup.service
   echo "#!/bin/bash" > /usr/bin/fakebackup.sh
   echo "echo 'Performing fake backup...'" >> /usr/bin/fakebackup.sh
   chmod +x /usr/bin/fakebackup.sh
   systemctl enable fakebackup.service

   # Hidden Malware
   echo "*/15 * * * * root echo 'MALWARE EXECUTED' >> /tmp/malware.log" > /etc/cron.d/malware
   chmod 777 /tmp

   # File System Issues
   chmod 777 /etc/passwd /etc/shadow /var/log/auth.log
   mkdir -p /home/student1/.hidden
   echo "Sensitive API keys" > /home/student1/.hidden/api_keys.txt

   # Binary Exploits
   echo "#!/bin/bash" > /usr/local/bin/exploit
   echo "chmod 777 /etc/shadow" >> /usr/local/bin/exploit
   chmod +x /usr/local/bin/exploit
   chmod u+s /usr/local/bin/exploit

   # Simulate Network Traffic
   nohup nc -lk 5555 > /dev/null 2>&1 &

   # Fake Logs
   echo "Failed password for root from 192.168.1.200 on port 22" >> /var/log/auth.log

   # Vulnerable Backup Scripts
   echo "#!/bin/bash" > /usr/bin/vulnbackup.sh
   echo "cp /etc/shadow /tmp/shadow.bak" >> /usr/bin/vulnbackup.sh
   chmod +x /usr/bin/vulnbackup.sh

   # Forensics Questions
   echo "Creating forensics questions on desktop..."
   mkdir -p /home/student1/Desktop
   for i in {1..10}; do
       touch /home/student1/Desktop/forensics${i}.txt
   done

   cat <<EOL > /home/student1/Desktop/forensics1.txt
   Forensics Question 1:
   ---------------------
   What is the last IP address that logged into the SSH server?

   Answer here:
   EOL

   chown -R student1:student1 /home/student1/Desktop

   # Final Message
   echo "Advanced CyberPatriot practice image setup complete!"
   echo "Forensics questions are placed on student1's desktop and can be answered in text files."
   ```

3. Run the script:
   ```bash
   sudo chmod +x cyberpatriot_setup.sh
   sudo ./cyberpatriot_setup.sh
   ```

---

## **3. Install and Configure Aeacus**

1. Download and install Aeacus:
   ```bash
   wget https://github.com/elysium-suite/aeacus/releases/download/v2.1.1/aeacus-linux.zip -O /tmp/aeacus-linux.zip
   unzip /tmp/aeacus-linux.zip -d /opt/aeacus
   chmod +x /opt/aeacus/aeacus
   ```

2. Create the scoring configuration file:
   ```bash
   nano /opt/aeacus/scoring.toml
   ```

3. Paste the following configuration:
   ```json
   [name = "CyberPatriot Advanced Practice Image"
   title = "Advanced Image"
   os = "Ubuntu 20.04"
   user = "student1"
   version = "1.0.0"
   
   [[check]]
   message = "Unauthorized user 'hacker' has been removed."
   points = 5
   [[check.pass]]
   type = "UserExistsNot"
   user = "hacker"
   
   [[check]]
   message = "Unauthorized user 'backdoor' has been removed."
   points = 5
   [[check.pass]]
   type = "UserExistsNot"
   user = "backdoor"
   
   [[check]]
   message = "Weak password for 'admin' has been fixed."
   points = 5
   [[check.pass]]
   type = "PasswordHashNot"
   user = "admin"
   hash = "$1$"
   
   [[check]]
   message = "Root login via SSH has been disabled."
   points = 10
   [[check.pass]]
   type = "FileContainsNot"
   path = "/etc/ssh/sshd_config"
   value = "PermitRootLogin yes"
   
   [[check]]
   message = "Apache directory listing has been disabled."
   points = 10
   [[check.pass]]
   type = "FileContainsNot"
   path = "/etc/apache2/apache2.conf"
   value = "Options Indexes"
   
   [[check]]
   message = "Malicious cron job has been removed."
   points = 10
   [[check.pass]]
   type = "PathExistsNot"
   path = "/etc/cron.d/malware"
   
   [[check]]
   message = "Samba share is properly secured."
   points = 10
   [[check.pass]]
   type = "FileContainsNot"
   path = "/etc/samba/smb.conf"
   value = "writable = yes"
   
   [[check]]
   message = "Hidden directory has been removed."
   points = 5
   [[check.pass]]
   type = "PathExistsNot"
   path = "/home/student1/.hidden"
   
   [[check]]
   message = "Unauthorized netcat listener has been disabled."
   points = 5
   [[check.pass]]
   type = "PortListeningNot"
   port = 5555
   
   [[check]]
   message = "Forensics Question 1: Correct answer provided."
   points = 5
   [[check.pass]]
   type = "FileContains"
   path = "/home/student1/Desktop/forensics1.txt"
   value = "192.168.1.200"
   
   [[check]]
   message = "Forensics Question 2: Correct answer provided."
   points = 5
   [[check.pass]]
   type = "FileContains"
   path = "/home/student1/Desktop/forensics2.txt"
   value = "Sensitive API keys"
   
   [[check]]
   message = "Forensics Question 3: Correct answer provided."
   points = 5
   [[check.pass]]
   type = "FileContains"
   path = "/home/student1/Desktop/forensics3.txt"
   value = "vuln_user"
   
   [[check]]
   message = "Forensics Question 4: Correct answer provided."
   points = 5
   [[check.pass]]
   type = "FileContains"
   path = "/home/student1/Desktop/forensics4.txt"
   value = "*/15 * * * * root echo"
   
   [[check]]
   message = "Forensics Question 5: Correct answer provided."
   points = 5
   [[check.pass]]
   type = "FileContains"
   path = "/home/student1/Desktop/forensics5.txt"
   value = "Top Secret!"
   ]
```

4. Test Aeacus:
   ```bash
   /opt/aeacus/aeacus --verbose validate /opt/aeacus/scoring.toml
   ```

5. Run the scoring engine:
   ```bash
   /opt/aeacus/aeacus --verbose score
   ```

---

## **4. Prepare for Distribution**

1. Create a snapshot of the VM to preserve the vulnerable state.
2. Distribute instructions to participants on accessing the VM and running Aeacus.

---

Let me know if you need further adjustments or refinements!
