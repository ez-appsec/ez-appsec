// True negative: JSON.parse is safe
app.post('/import', (req, res) => {
    // ok: ez-express-insecure-deserialization
    const obj = JSON.parse(req.body.data);
    res.json(obj);
});
