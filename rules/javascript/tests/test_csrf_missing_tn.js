// True negative: GET route (no CSRF needed, safe)
const express = require('express');
const app = express();

// ok: ez-express-no-csrf
app.get('/status', function(req, res) {
    res.json({status: 'ok'});
});
