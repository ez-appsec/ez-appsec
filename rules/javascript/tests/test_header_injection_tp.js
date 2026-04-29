// True positive: user input in response header
const express = require('express');

app.get('/set-lang', (req, res) => {
    // ruleid: ez-express-header-injection
    res.setHeader('Content-Language', req.query.lang);
    res.send('OK');
});
