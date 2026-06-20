// True negative: scoped to current user (safe)
const express = require('express');

app.get('/invoice/:id', async (req, res) => {
    // ok: ez-express-idor-param
    const invoice = await Invoice.findOne({
        _id: req.params.id,
        userId: req.user.id
    });
    res.json(invoice);
});
