/* 

An encryption mechanism that creates a hash using JSON payload
HMAC is only for hashing a string or an object and it can not
decrypt the message. To encrypt or decrypt  use Cipher

*/

const express = require('express');
const { createHmac } = require('node:crypto');
const hmacVerify = require('./middlewares/hmacVerify.js');

require('dotenv').config();

const app = express();
const port = 8080;

app.use(express.json());

app.post('/create/hash', (req, res) => {
  const { body } = req;

  if (typeof body !== 'object') {
    //
    // ---> Since we are using json objects
    //      an object is required to create a hash

    res.status(400).json({
      message: `An object with secret key/value pairs is needed to generate a hash`,
    });
  } else {
    //
    // create a hash that encloses any secret info
    //
    const hash = createHmac('sha256', process.env.SECRET)
      .update(JSON.stringify(body))
      .digest('base64');

    // ------> an important thing to note here is that the hash
    //         will remain same for this data provided
    //         if someone supplies the same data object
    //         then protected route can be accessed

    res.status(201).json({
      hash,
      message: 'Include this in req headers as "x-hash-in-header"',
    });
  }
});

app.get('/protected', hmacVerify, (req, res) => {
  // ----> hash in request header is verified and
  //       protected route is opened

  res.json({ message: 'Your are now visting a protected route' });
});

app.listen(port, () => {
  console.log(`----> Serving listening on localhost:${port}`);
});
