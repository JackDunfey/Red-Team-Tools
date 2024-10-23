from os import popen, system
descriptions = [
    "netwatcher: Monitors network traffic and usage statistics for local and remote connections.",
    "filemanagerd: Manages file operations and directory structures for user applications.",
    "cloudsync: Synchronizes local data with cloud storage services in real time.",
    "datastreamer: Transfers large datasets between servers or databases over network protocols.",
    "logmonitord: Continuously tracks and reports system log events to administrators.",
    "usertrack: Monitors user activity and session durations on a multi-user system.",
    "cachecleaner: Periodically cleans up unused or expired cache files to free up memory.",
    "dbsyncer: Ensures real-time synchronization of databases across multiple nodes.",
    "conntracker: Tracks active network connections and their corresponding processes.",
    "authservice: Manages authentication requests and user session validation.",
    "taskmonitor: Oversees running processes and handles system task scheduling.",
    "configmanager: Centralized management for application and system configuration files.",
    "pkgupdater: Automatically checks and updates installed software packages.",
    "diskwatcher: Monitors disk health and usage, reporting anomalies or potential failures.",
    "procmon: Tracks system processes and their resource consumption.",
    "sysloghandler: Routes and filters system logs to the appropriate locations.",
    "appservice: Manages and coordinates background services for user applications.",
    "deviced: Provides device management and coordination between the kernel and user space.",
    "notifcenter: Centralized notification system for system alerts and messages.",
    "cronmanager: Manages scheduled tasks and automates system maintenance jobs.",
    "diskmapper: Maps disk partitions and ensures their proper mounting at boot time.",
    "networkguard: Security service that monitors and guards against unauthorized network activity.",
    "proxymanager: Manages proxy services and forwards requests between networks.",
    "sesshandler: Manages user sessions and related data across login and logout events.",
    "backupagent: Coordinates scheduled backups of system files and databases.",
    "processwatcher: Monitors running system processes and ensures they are within resource limits.",
    "alertmanager: Handles alert notifications from various system services and sends them to administrators.",
    "eventhandler: Listens for system events and triggers corresponding actions based on predefined rules.",
    "storagemapper: Maps and organizes access to physical and virtual storage volumes.",
    "dnsforwarder: Forwards DNS queries from clients to external DNS servers.",
    "maild: Provides email delivery services for applications and system notifications.",
    "perfwatcher: Monitors system performance metrics like CPU, memory, and disk usage.",
    "replicad: Manages data replication between multiple servers for redundancy.",
    "queuemanager: Manages task queues for distributed systems or applications.",
    "datadispatcher: Distributes and directs data between various system components.",
    "datahub: Acts as a central point for aggregating and redistributing data from various sources.",
    "keyserviced: Manages encryption keys and certificates for secure data transmission.",
    "eventlogger: Records system events for auditing and diagnostics.",
    "loadbalancer: Balances traffic loads across multiple servers to optimize performance.",
    # "secureproxy: Acts as a secure proxy for forwarding sensitive traffic with encryption.",
    "auditlogger: Logs and tracks changes to system files and configurations for audit purposes.",
    "alertd: Daemon that triggers alerts based on system performance or security thresholds.",
    "usermonitor: Monitors user activities, such as logins, logouts, and file access.",
    "schedulerd: Manages the scheduling of jobs, scripts, and background tasks.",
    "cfgsync: Synchronizes configuration files across multiple systems to ensure consistency.",
    "patchmanager: Manages the deployment of software patches and updates to the system.",
    "vaultservice: Manages secure storage of sensitive information, such as passwords and encryption keys.",
    "ipforward: Manages IP forwarding and routing rules for the system.",
    # "tunneld: Manages encrypted tunnels for secure remote connections.",
    "cloudkeeper: Ensures that cloud storage is kept in sync and available at all times.",
    "logaggregator: Collects logs from various services and centralizes them for analysis.",
    "syncagent: Coordinates synchronization tasks between distributed systems.",
    "routeguard: Secures and manages routing rules on network devices.",
    "dataextractor: Extracts and processes data from remote databases and APIs.",
    "certmanager: Manages SSL/TLS certificates for secure communications.",
    "metricsagent: Collects and reports system performance metrics to a monitoring dashboard.",
    "reporter: Generates and distributes system reports on performance, logs, and security.",
    # "taskqueue: Manages and schedules tasks that need to be processed in order.",
    "dataclient: Acts as a client for fetching and processing remote data streams.",
    "auditd: Daemon responsible for logging and monitoring audit events on the system.",
    "secureproxy: Handles secure proxying of traffic for protected internal services.",
    "connwatch: Watches network connections and flags suspicious activity or anomalies.",
    "filetracker: Monitors file access, modification, and permission changes across the system.",
    "netguard: Secures the network against attacks by monitoring and filtering traffic.",
    "cloudconnect: Manages secure connections to cloud services and APIs.",
    "pkgmanager: Handles software package installations, removals, and updates.",
    "fileserviced: Provides file sharing services across the local network.",
    "mailqueue: Manages email queues for outgoing messages, ensuring delivery.",
    "indexer: Indexes system files and directories for faster searching and access.",
    "cryptowatcher: Monitors system encryption processes and key usage for security.",
    "datagateway: Acts as a gateway for data requests between clients and databases.",
    "tokenservice: Issues and validates authentication tokens for secure communication.",
    # "certwatcher: Monitors certificate expiration dates and triggers renewals as needed.",
    "backupservice: Manages scheduled and on-demand backups of critical data.",
    "fileserverd: Provides file serving capabilities for remote access.",
    "tunneld: Manages secure tunneling protocols for remote connections.",
    "queueagent: Coordinates tasks in distributed task queues for parallel processing.",
    "alertservice: Manages alert notifications from system components and services.",
    "logmanager: Organizes and filters logs from multiple sources for easy access.",
    "streamcontroller: Manages and monitors data streams between services.",
    "proxd: Acts as an intermediary proxy for forwarding requests between networks.",
    "persistenceagent: Ensures persistent storage and recovery for critical data.",
    "dnsmanager: Configures and manages DNS settings and forwarding rules.",
    "logcleaner: Cleans up old or unused log files to free up disk space.",
    "authagent: Manages authentication requests for users and applications.",
    "cloudmonitor: Tracks and reports the status of cloud-hosted resources.",
    "filesyncer: Synchronizes files between different directories or remote locations.",
    "servicemonitor: Monitors the health and status of system services, restarting as needed.",
    "keymanager: Manages encryption keys and their usage in the system.",
    "remotesync: Synchronizes data with remote servers for backup or distribution.",
    "backupdaemon: Manages and runs backup tasks based on scheduled intervals.",
    "schedmanager: Coordinates scheduling and task execution across the system.",
    "dbwatcher: Monitors database health and reports anomalies or failures.",
    "pkgfetcher: Fetches software packages from remote repositories for installation.",
    "cachemonitor: Monitors cache usage and performance, clearing it when needed.",
    "cloudnotifier: Sends notifications about changes in cloud resource status.",
    "dataconnector: Connects and transfers data between local and remote databases.",
    "remoteservice: Provides services to remote clients for data access and processing.",
    "alertwatcher: Watches for alerts generated by system components and services.",
    # "keyserviced: Handles secure storage and access to encryption keys.",
    "configsync: Ensures configuration files are synced across multiple systems.",
    "eventdispatcher: Dispatches system events to the appropriate handlers or listeners.",
    "sslservice: Manages SSL/TLS encryption and certificates for secure communications.",
    "certstore: Stores and manages SSL/TLS certificates for system services.",
    "queuemaster: Manages and oversees task queues in distributed environments.",
    "diskguard: Monitors disk health and flags issues like bad sectors or low space.",
    "networkcleaner: Cleans up inactive network connections and routes to maintain performance.",
    "taskrunner: Runs scheduled tasks and background processes for the system.",
    "vpnwatcher: Monitors VPN connections and ensures secure tunneling.",
    "connmonitor: Monitors the status of active network connections and flags issues.",
    "datashare: Manages data sharing between local and remote services or users.",
    "datamonitor: Tracks data flow and usage within the system for performance optimization.",
    "connmanager: Manages active network connections and ensures stability.",
    "memwatcher: Monitors memory usage and performance across the system.",
    "dataproxy: Acts as an intermediary for data requests between clients and servers.",
    "logforwarder: Forwards logs from local services to remote log aggregators.",
    "sysmonitord: Monitors system-wide performance metrics and resource usage.",
    "taskqueue: Handles task scheduling for distributed systems and ensures tasks are processed in order.",
    "monitoringagent: Collects and reports system monitoring metrics to external tools.",
    "certwatcher: Tracks SSL certificate expiration and issues renewal requests.",
    "secureagent: Provides security services such as encryption, token management, and secure connections."
]

with open("./template.service", 'r') as f:
    template = f.read()

system("gcc ./do_nothing.c -o ./template_exec")
for desc in descriptions:
    try:
        name, description = desc.split(": ")
        ExecPath = f"/var/lib/{name}"
        system(f"cp ./template_exec {ExecPath}")
        with open(f"/etc/systemd/system/{name}.service", 'w+') as f:
            f.write(template.replace("{{Description}}", description).replace("{{ExecStart}}", ExecPath))

        system(f"systemctl start {name}")
        system(f"systemctl enable {name}")
    except:
        pass