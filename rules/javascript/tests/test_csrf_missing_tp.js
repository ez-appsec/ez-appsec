// True positive: POST route without CSRF middleware
const express = require('express');
const app = express();

// ruleid: ez-express-no-csrf
app.post('/transfer', function(req, res) {
    doTransfer(req.body.amount);
    res.json({ok: true});
});
