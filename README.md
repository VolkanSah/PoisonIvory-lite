# Feuerteufel
###### RedTeam Script (EDU) by Volkan Sah - simple codings for 'Offensive Security' (updated 5/2023)

Feuerteufel is a small Python script that demonstrates how to intercept requests and execute additional actions when accessed through the Tor network. The script is designed to showcase the interception capability and provides a template for further customization. However, it is important to note that engaging in such activities can have serious legal and ethical implications.

### WARNING: USE AT YOUR OWN RISK!
Please read the following warnings and considerations carefully before proceeding:

- Legal Compliance: Interfering with network traffic and executing external scripts without proper authorization can be illegal in many jurisdictions. Ensure that you fully understand and comply with the laws and regulations of your country or region before using this script.

- Ethical Responsibility: Respect the privacy and security of others. Do not use this script for malicious purposes, personal gain, or any activity that could cause harm or violate the rights of individuals or organizations. It is crucial to conduct ethical testing and obtain appropriate consent before performing any actions that may impact systems or networks.

- Personal Liability: The author of this script cannot be held responsible for any misuse, damages, legal issues, or consequences resulting from the use of this script. By using InterceptAPI, you assume full responsibility for your actions and any outcomes that may arise.

### Note 
This script is intended for educational and informational purposes only. It serves as a starting point for understanding API interception techniques and should be used responsibly and legally.

## Tor Traffic Monitoring Script

This script monitors and intercepts Tor traffic to detect and handle malicious activity. It utilizes the Scapy and Stem libraries to analyze network packets and interact with the Tor network.

## Features

- Monitors and intercepts Tor traffic in real-time.
- Detects malicious traffic based on specified keywords.
- Executes an external script for further analysis or actions like attacks
- Excludes malicious Tor relays from the circuit.

## Prerequisites

- Python 3.x
- Scapy library (`pip install scapy`)
- Stem library (`pip install stem`)

## Usage

1. Set the desired `.onion` address to monitor in the `onion_address` variable.
2. Customize the keywords for detecting malicious traffic in the `MaliciousTrafficListener` class.
3. Run the script and observe the output for detected malicious traffic.
4. Customize the `intercept_api_requests` function to handle intercepted API requests.
5. Adjust the local address or URL of the external script as needed.
6. Execute the `exclude_malicious_relays` function to add malicious relays to the circuit blacklist or create a whitelist with it 😅

## Important Note

Executing code fetched from the internet or local sources can be risky. 
Ensure that you trust the source and contents of the external script before loading and executing it.

## How it Works
InterceptAPI utilizes the power of Python, Scapy, and Stem libraries to intercept API requests and perform additional actions. When accessed through the Tor network, the script can load and run an external script from a specified URL. It provides a basic framework that can be customized to meet specific requirements or integrate with other security tools.


## Acknowledgements

- This script utilizes the Scapy and Stem libraries.
- Thanks to the open-source community for their contributions.

## issues
Issues to this script are not accepted as it is intended for educational purposes only and not for production use.

### Thank you for your support!
- If you appreciate my work, please consider [becoming a 'Sponsor'](https://github.com/sponsors/volkansah), giving a :star: to my projects, or following me. 
### Copyright
- [VolkanSah on Github](https://github.com/volkansah)
- [Developer Site](https://volkansah.github.io)


## Disclaimer
This script is provided as-is, without any warranties or guarantees. The author cannot be held responsible for any damages, legal consequences, or misuse arising from the use of this script. Use it responsibly, respect the law, and always consider the potential impact on privacy, security, and the rights of others.

Remember: Be a responsible developer and prioritize the security and well-being of others!
