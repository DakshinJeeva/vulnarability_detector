VULNERABILITY: XSS
PATTERN: Stored XSS in forum and chat applications
CWE: CWE-79
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
Chat messages, forum posts, thread titles (req.body.message, req.body.title)

SINK:
Real-time message display, forum thread rendering

DESCRIPTION:
Stored XSS in forums and chats occurs when malicious scripts are posted
as messages or thread content and automatically execute for all users
viewing the conversation. This creates self-propagating (worm-type) XSS
as the payload spreads to every participant.

WHY_THIS_IS_DANGEROUS:
- Affects all conversation participants
- Self-propagating in real-time chats
- Can create XSS worms that auto-post
- Spreads rapidly across user base
- Real-time nature makes detection harder

DETECTION_RULE:
Flag when:
- Chat messages stored and rendered without sanitization
- WebSocket messages displayed without encoding
- Forum posts rendered with innerHTML
- Markdown rendering without XSS protection

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Messages sanitized with DOMPurify before storage
- Markdown renderers use XSS-safe libraries
- Template engines auto-escape message content
- Content Security Policy blocks inline scripts

EXAMPLE_VULNERABLE_CODE:
```js
const io = require('socket.io')(server);

io.on('connection', (socket) => {
  socket.on('chat message', (msg) => {
    const message = msg.text;
    const username = msg.username;
    
    db.query("INSERT INTO messages (username, text) VALUES (?, ?)", 
      [username, message]);
    
    // Broadcast to all users
    io.emit('chat message', { username, message });
  });
});

// Client-side (vulnerable)
socket.on('chat message', (data) => {
  const item = document.createElement('li');
  item.innerHTML = `<strong>${data.username}:</strong> ${data.message}`;
  messages.appendChild(item);
});
```

EXAMPLE_SAFE_CODE:
```js
const io = require('socket.io')(server);
const DOMPurify = require('isomorphic-dompurify');
const escapeHtml = require('escape-html');

io.on('connection', (socket) => {
  socket.on('chat message', (msg) => {
    const message = DOMPurify.sanitize(msg.text, { 
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: []
    });
    const username = escapeHtml(msg.username);
    
    db.query("INSERT INTO messages (username, text) VALUES (?, ?)", 
      [username, message]);
    
    io.emit('chat message', { username, message });
  });
});

// Client-side (safe)
socket.on('chat message', (data) => {
  const item = document.createElement('li');
  const strong = document.createElement('strong');
  strong.textContent = data.username + ': ';
  item.appendChild(strong);
  item.appendChild(document.createTextNode(data.message));
  messages.appendChild(item);
});
```