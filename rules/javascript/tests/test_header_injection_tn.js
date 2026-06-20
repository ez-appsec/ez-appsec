// True negative: hardcoded header value (safe)
const express = require('express');

app.get('/set-lang', (req, res) => {
    // ok: ez-express-header-injection
    res.setHeader('Content-Language', 'en-US');
    res.send('OK');
});
