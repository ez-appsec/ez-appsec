// True positive: mass assignment via req.body spread
const express = require('express');

app.post('/users', async (req, res) => {
    // ruleid: ez-express-mass-assignment
    const user = await User.create(req.body);
    res.json(user);
});
