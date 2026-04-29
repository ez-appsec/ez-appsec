// True positive: IDOR via direct findById without ownership check
const express = require('express');

app.get('/invoice/:id', async (req, res) => {
    // ruleid: ez-express-idor-param
    const invoice = await Invoice.findById(req.params.id);
    res.json(invoice);
});
