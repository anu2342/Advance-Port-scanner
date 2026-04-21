# 🔍 Advanced Port Scanner with CVE Detection

## 📌 Overview

This project is a **multi-threaded advanced port scanner** built in Python.
It not only scans open ports but also performs:

* Service detection
* Version fingerprinting
* CPE generation
* CVE (vulnerability) lookup using NVD API

The tool helps in **basic vulnerability assessment and security analysis**.

---

## 🚀 Features

* ⚡ Fast multi-threaded port scanning
* 🔎 Service & product fingerprinting
* 🧠 Automatic version extraction from banners
* 🔗 CPE (Common Platform Enumeration) generation
* 🛡️ CVE lookup from NVD database
* 📊 Severity classification (Low, Medium, High, Critical)
* 📁 JSON report generation
* 🖥️ Clean terminal output

---

## 🛠️ Technologies Used

* Python 3
* Socket Programming
* Multithreading
* REST API (NVD CVE API)
* SSL/TLS handling

---

## 📂 Project Structure

```
advance port scanner.py   # Main scanner script
report.json               # Output report (generated after scan)
```

---

## ⚙️ Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/advanced-port-scanner.git
cd advanced-port-scanner
```

2. Install dependencies:

```bash
pip install requests
```

---

## ▶️ Usage

Run the script:

```bash
python "advance port scanner.py"
```

Enter the target:

```
Enter target IP/domain: example.com
```

---

## 📊 Sample Output

```
PORT: 80
  Service : http
  Product : apache
  Version : 2.4.41
  CPE     : cpe:2.3:a:apache:apache:2.4.41:*:*:*:*:*:*:*
  CVEs:
    - CVE-XXXX-XXXX | HIGH | CVSS: 7.5
```

---

## 📁 Output Report

After scan completion, a file will be generated:

```
report.json
```

It contains:

* Target details
* Scan timestamp
* Open ports
* Services & versions
* CVEs with severity

---

## 🔐 Configuration

You can modify these parameters in the script:

```python
PORT_RANGE = range(1, 1025)
THREADS = 100
TIMEOUT = 2
NVD_API_KEY = ""
```

👉 Add your NVD API key for better performance:

```
https://nvd.nist.gov/developers/request-an-api-key
```

---

## ⚠️ Disclaimer

This tool is intended for **educational and ethical use only**.

* Do NOT scan systems without permission
* Unauthorized scanning may be illegal

---

## 💡 Future Improvements

* OS detection
* UDP scanning
* GUI version
* Export to PDF/HTML reports
* Integration with exploit databases

---

## 👨‍💻 Author

**Your Name**
Cybersecurity Enthusiast | VAPT Learner

---

## ⭐ Contribute

Pull requests are welcome. For major changes, open an issue first.

---

## 📜 License

This project is licensed under the MIT License.
