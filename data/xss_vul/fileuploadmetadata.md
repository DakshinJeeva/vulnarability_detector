VULNERABILITY: XSS
PATTERN: Stored XSS in file upload metadata
CWE: CWE-79
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
File upload metadata (filename, EXIF data, Content-Type, file description)

SINK:
File listing pages, download links, image galleries displaying metadata

DESCRIPTION:
Stored XSS in file metadata occurs when malicious scripts are embedded
in filenames, EXIF data, or file descriptions during upload. When these
metadata fields are displayed without sanitization, the scripts execute
for users viewing file listings or galleries.

WHY_THIS_IS_DANGEROUS:
- Filenames often displayed without sanitization
- EXIF data can contain arbitrary strings
- Affects all users viewing file listings
- Can persist across file downloads/shares
- Bypasses content-based XSS filters

DETECTION_RULE:
Flag when:
- Original filename displayed without encoding
- EXIF metadata rendered to HTML
- File descriptions shown without sanitization
- Content-Disposition header contains unsanitized filename

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Filenames sanitized on upload (alphanumeric only)
- Metadata stripped before storage
- Output encoded when displaying file info
- Template engines auto-escape metadata

EXAMPLE_VULNERABLE_CODE:
```js
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
  const filename = req.file.originalname;
  const description = req.body.description;
  
  db.query("INSERT INTO files (filename, description) VALUES (?, ?)", 
    [filename, description]);
  res.send("File uploaded");
});

app.get('/files', (req, res) => {
  db.query("SELECT * FROM files", (err, files) => {
    let html = "<ul>";
    files.forEach(file => {
      html += `<li><a href="/download/${file.id}">${file.filename}</a> - ${file.description}</li>`;
    });
    html += "</ul>";
    res.send(html);
  });
});
```

EXAMPLE_SAFE_CODE:
```js
const multer = require('multer');
const path = require('path');
const sanitize = require('sanitize-filename');
const escapeHtml = require('escape-html');

const storage = multer.diskStorage({
  filename: (req, file, cb) => {
    const safeName = sanitize(file.originalname);
    cb(null, Date.now() + '-' + safeName);
  }
});
const upload = multer({ storage });

app.post('/upload', upload.single('file'), (req, res) => {
  const filename = sanitize(req.file.originalname);
  const description = escapeHtml(req.body.description);
  
  db.query("INSERT INTO files (filename, description) VALUES (?, ?)", 
    [filename, description]);
  res.send("File uploaded");
});

app.get('/files', (req, res) => {
  db.query("SELECT * FROM files", (err, files) => {
    res.render('files', { files }); // Template auto-escapes
  });
});
```