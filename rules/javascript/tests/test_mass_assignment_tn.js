// True negative: explicit field pick (safe)
const express = require('express');

app.post('/users', async (req, res) => {
    // ok: ez-express-mass-assignment
    const user = await User.create({
        name: req.body.name,
        email: req.body.email,
    });
    res.json(user);
});
