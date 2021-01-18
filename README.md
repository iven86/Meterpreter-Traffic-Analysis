<h1 align="center">Malware Traffic Analysis With Python</h1>
<p align="center">
    <a href="https://github.com/iven86/Meterpreter-Traffic-Analysis/blob/main/LICENSE">
    <img alt="GitHub license" src="https://img.shields.io/github/license/iven86/Meterpreter-Traffic-Analysis"></a>
    <a href="https://github.com/iven86/Meterpreter-Traffic-Analysis/network">
    <img alt="GitHub forks" src="https://img.shields.io/github/forks/iven86/Meterpreter-Traffic-Analysis"></a>
    <a href="https://github.com/iven86/Meterpreter-Traffic-Analysis/stargazers">
    <img alt="GitHub stars" src="https://img.shields.io/github/stars/iven86/Meterpreter-Traffic-Analysis"></a>
    <img src="https://img.shields.io/github/languages/top/iven86/Meterpreter-Traffic-Analysis" />
</p>

<h2>Meterpreter Traffic Analysis With Python</h2>
- A very simple Python script to analyse http reverse traffic from Meterpreter
- In my sample I going to analyze traffic for "windows/meterpreter/reverse_https" for more details about this Meterpreter go to:
- https://blog.rapid7.com/2011/06/29/meterpreter-httphttps-communication/

> Screenshot Of Resultes:
![alt text](https://raw.githubusercontent.com/iven86/Meterpreter-Traffic-Analysis/main/img/Screenshot01.png)

## 🚀 Behind The Scene:
- At first we have to convert PCAP file to json with filter or without by run one of these commands:
- tshark -2 -R "http.request.method==GET or http.request.method==POST" -r input.pcap -T json >output.json
- tshark -2 -R "ip.addr==X.X.X.X and http.request.method==GET" -r input.pcap -T json >output.json
- Sometimes you need to fix json file after running on of above commands.
- The process is we going to all hosts on HTTP layers and check them with Metasploit User_Agent (Be sure it's a changable by attacker).

## ✨ The Accuracy:
- Not granted 100%, This project just an idea, and all results based on https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/user_agent.rb.

## Author

👤 **Iven Leni Fernandez**

- Twitter: [@iven86](https://twitter.com/iven86)
- Github: [@iven86](https://github.com/iven86)
- Linkedin: [@iven86](https://www.linkedin.com/in/iven86/)

## ✨ Support Me or buy me a Coffee:
- paypal.me/iven86

## 📝 License
Copyright © 2021 [Iven Leni Fernandez](https://github.com/iven86).<br />
This project is [AGPL-3.0](https://github.com/iven86/Meterpreter-Traffic-Analysis/blob/main/LICENSE) licensed.
