// True positive: node-serialize unserialize on user input
const serialize = require('node-serialize');

app.post('/import', (req, res) => {
    // ruleid: ez-express-insecure-deserialization
    const obj = serialize.unserialize(req.body.data);
    res.json(obj);
});
